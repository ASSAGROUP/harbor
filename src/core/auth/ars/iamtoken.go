package ars

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/goharbor/harbor/src/common/models"
	"github.com/goharbor/harbor/src/common/utils/log"
	authenticationapi "k8s.io/api/authentication/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	iamauthtoken "sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

const (
	V1Prefix               = "k8s-aws-v1."
	dateHeaderFormat       = "20060102T150405Z"
	presignedURLExpiration = 15 * time.Minute
)

// The AWS IAM token can be obtained by "aws eks get-token" command. It's used by kubectl.
// The ack CLI generates the token with AWS node.js sdk.
func authenticateByAwsIamToken(m models.AuthModel) (*models.User, error) {

	identity, ttl, err := verifyToken(m.Principal, m.Password)
	if err != nil {
		log.Errorf("failed to verify token. %v", err)
		return nil, err
	}

	// token is valid
	if identity != nil {
		// get the mapped kubernetes user, e.g. eks-admin
		k8sUserName, err := whoAmI(m.Password)
		if err != nil {
			log.Errorf("failed to get the mapped kubernetes username for IAM user %s. %v", m.Principal, err)
			return nil, err
		}
		return createUserForIamUser(m, k8sUserName, identity, ttl), nil
	}

	return nil, errors.New("failed to get caller identity")

}

// create the harbor user object from collected data
func createUserForIamUser(m models.AuthModel, k8sUserName string, identity *iamauthtoken.Identity, ttl *time.Duration) *models.User {

	mUser := &models.User{
		Username: m.Principal,
		Password: getDigest(m.Password),
		Realname: identity.ARN,
		Email:    m.Principal,
		Comment:  UserTypeIAMUser, // Comment is used to store user type (like for DOSA token)
		Salt:     k8sUserName,     // Salt is used to store kubernetes username (this field is not used for now)
	}

	mUser.Rolename = roleNameDeveloper
	mUser.HasAdminRole = false
	mUser.Role = 2

	// use ResetUUID to store next time (last auth time + ttl) for auth against backend again (ARS-4919)
	mUser.ResetUUID = time.Now().Add(*ttl).Format(time.RFC3339)
	return mUser
}

// verify token with aws-iam-authenticator against AWS STS
func verifyToken(iamUser string, token string) (*iamauthtoken.Identity, *time.Duration, error) {

	callerIdentity, err := getCallerIdentity(token)
	if err != nil {
		return nil, nil, err
	}

	minutesToLive, err := getTokenValidTime(token)
	if err != nil {
		log.Errorf("failed to get token valid time. %v", err)
		return callerIdentity, nil, err
	}

	return callerIdentity, minutesToLive, nil
}

// verify token against AWS STS (GetCallerIdentity API)
// https://github.com/kubernetes-sigs/aws-iam-authenticator/blob/375e2c907aad3b6c82aab79e555ddd13cff870ba/pkg/token/token.go
func getCallerIdentity(token string) (*iamauthtoken.Identity, error) {

	clusterID := os.Getenv("CLUSTER_ID")
	log.Debugf("verify token to get caller identity. clusterID: %s", clusterID)

	if clusterID == "" {
		return nil, errors.New("clusterID is missing in configuration")
	}

	verifier := iamauthtoken.NewVerifier(clusterID, "aws")

	identity, err := verifier.Verify(token)
	if err != nil {
		// input token was not properly formatted: X-Amz-Date parameter is expired (15 minute expiration) 2021-11-18 07:11:46 +0000 UTC
		log.Errorf("failed to verify token. %v", err)
		return nil, err
	}

	log.Debugf("identity: %s", identity)
	/*
	   {
	   	"ARN": "arn:aws:sts::654814900965:assumed-role/eks-admin/EKSGetTokenAuth",
	   	"CanonicalARN": "arn:aws:iam::654814900965:role/eks-admin",
	   	"AccountID": "654814900965",
	   	"UserID": "AROAZQ5QCOLSYBZQRRSCZ",
	   	"SessionName": "EKSGetTokenAuth",
	   	"AccessKeyID": "ASIAZQ5QCOLSSDCAXDE2"
	   }
	*/

	return identity, nil
}

// calculate the minutes to live for a token.
// https://github.com/kubernetes-sigs/aws-iam-authenticator/blob/375e2c907aad3b6c82aab79e555ddd13cff870ba/pkg/token/token.go
func getTokenValidTime(token string) (*time.Duration, error) {

	tokenBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, V1Prefix))
	if err != nil {
		return nil, err
	}

	parsedURL, err := url.Parse(string(tokenBytes))
	if err != nil {
		return nil, err
	}

	queryParamsLower := make(url.Values)
	queryParams, err := url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		return nil, err
	}

	for key, values := range queryParams {
		queryParamsLower.Set(strings.ToLower(key), values[0])
	}

	date := queryParamsLower.Get("x-amz-date")
	if date == "" {
		return nil, err
	}

	dateParam, err := time.Parse(dateHeaderFormat, date)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	log.Debugf("dateParam: %v", dateParam)
	log.Debugf("now: %v", now)

	minutesToLive := dateParam.Add(presignedURLExpiration).Sub(now).Round(time.Minute)

	log.Debugf("the token has %v minutes to live", minutesToLive)

	return &minutesToLive, nil
}

//whoAmI returns the current user/token subject (kubernetes user name)
func whoAmI(token string) (string, error) {

	log.Debug("create token review to find out the kubernetes user...")

	result, err := k8sClientSet.AuthenticationV1().TokenReviews().Create(context.Background(),
		&authenticationapi.TokenReview{
			Spec: authenticationapi.TokenReviewSpec{
				Token: token,
			},
		}, metav1.CreateOptions{})

	if err != nil {
		log.Error(err)
		if k8serrors.IsForbidden(err) {
			return getUsernameFromError(err), nil
		}
		return "", err
	}

	// log.Infof("result: %s", utils.PrettyOutput(result))

	if result.Status.Error != "" {
		return "", fmt.Errorf(result.Status.Error)
	}

	return result.Status.User.Username, nil
}

func getUsernameFromError(err error) string {
	log.Warningf("get username from kubernetes error message:: %v", err)
	re := regexp.MustCompile(`^.* User "(.*)" cannot .*$`)
	return re.ReplaceAllString(err.Error(), "$1")
}
