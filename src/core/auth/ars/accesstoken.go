package ars

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Jeffail/gabs"
	"github.com/goharbor/harbor/src/common/models"
	"github.com/goharbor/harbor/src/common/utils/log"
)

// curl -v \
// -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUNXJfaUwwbWJXUWpFQS1JcWNDSkFKaXlia0k4V2xrUnd0YVFQV0ZlWjJJIn0.eyJqdGkiOiJlN2YyMmYzMS1iZTFkLTQyODQtODdlOS0yMzMxMmE0NWU0OGEiLCJleHAiOjE1NTIwMzE3MzAsIm5iZiI6MCwiaWF0IjoxNTUyMDI5OTMwLCJpc3MiOiJodHRwczovL2xvZ2luLXByZXByb2QuYXh3YXkuY29tL2F1dGgvcmVhbG1zL0Jyb2tlciIsImF1ZCI6ImFtcGxpZnktY2xpIiwic3ViIjoiMThjNTkwMmYtMzNlYi00YWVjLTlkZDktNjgxZGYzMGVjNjU1IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYW1wbGlmeS1jbGkiLCJhdXRoX3RpbWUiOjE1NTIwMjc4NDIsInNlc3Npb25fc3RhdGUiOiI0NDBiMTMzNi0xMGZjLTRiM2YtODg2Ni03MTQ0ODcwZTdlNzIiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiYWRtaW5pc3RyYXRvciIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYnJva2VyIjp7InJvbGVzIjpbInJlYWQtdG9rZW4iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sIm5hbWUiOiJZdXBpbmcgSmluIiwicHJlZmVycmVkX3VzZXJuYW1lIjoieWppbkBheHdheS5jb20iLCJnaXZlbl9uYW1lIjoiWXVwaW5nIiwiZmFtaWx5X25hbWUiOiJKaW4iLCJlbWFpbCI6InlqaW5AYXh3YXkuY29tIn0.lWCfrxHOatFSLSObnTWAKKQGg3BGNbFQh9Vq6XspV76r-cCErUyRtFQY5rMeEnHN1UKuXOa6MuFncEcgZo4ftX2MLHzmdH3CLCYED8a1FnDhTct0dXWoj9pR-0efJwEFWrh0mhRPSCMphiQKiqkr5VGm-Qh-vt3YDKGlT6zZdiCkej0g9QIq5GwakqeQxAF68795bigDZ9ju1d6Mr0XTMUzBKYU4gvwkdWtDa1xL-X-fePka7J-ZqwtofTp1bGT-moZkxRonXc4kevxrOK6w_yLcT1WMFtGYcYDlzRIxhfRT0kZTvUaqT8eKEZnnEgPDmS-ceQ_8LJHygGfbVWhqgA" \
// https://platform-preprod.axwaytest.net/api/v1/auth/findSession
/*
{
    "success": true,
    "result": {
        "sessionID": "_V7roKPcQQp4DiGFyyrvGQxkZYpRegkk",
        "_stoked": 1552274899424,
        "from": "web",
        "username": "yjin@axway.com",
        "token": "d1ym53fWqWcRDP/Q0PUVVACk6y4=",
        "guid": "18c5902f-33eb-4aec-9dd9-681df30ec655",
        "sid": "ab6c93eeb033ca978aa75253a004e901",
        "org_id": 100000295,
        "org": {
            "_id": "52756f308aa1e9a7e7402b92",
            "org_id": 100000295,
            "guid": "aca22ab5-d281-43b4-b90d-5c0259da34da",
            "name": "Appcelerator Staff",
            "admins": [
                "5855731d-7387-45f0-a579-553655f53ffc",
                ...
            ],
            "users": [
                "6d040d19-265a-4fa4-b582-b9dfc567dd94"
            ],
            "collaborators": [],
            "consumers": [],
            "nodeacs": [
                "7d06b301-1209-4545-a9c0-1ab5d14fd4db",
                ...
            ],
            "limit_users": 500,
            "start_date": null,
            "end_date": "2045-09-01T23:59:59.999Z",
            "active": true,
            "envs": [],
            "creator": "3bb0d0eb40ecf1b04099600a5f37f2b4",
            "created": "2013-10-29T16:47:31.385Z",
            "package": "enterprise",
            "limit_read_only_users": 0,
            "subscriptions": [
                {
                    "id": "040ede4f-a677-4a7b-80d9-43908e031151",
                    "product": "appdev",
                    "plan": "enterprise",
                    "start_date": null,
                    "end_date": "2045-09-01T23:59:59.999Z",
                    "entitlements": {
                        "apiRateMonth": 5000000000,
                        "pushRateMonth": 8640000,
                        "storageFilesGB": 100,
                        "storageDatabaseGB": 100,
                        "containerPoints": 4500,
                        "arrowPublish": true,
                        "eventRateMonth": 1000000000,
                        "daysDataRetained": 731,
                        "allowProduction": true,
                        "appDesigner": true,
                        "appPreview": true,
                        "hyperloop": true,
                        "nativeSDK": true,
                        "premiumModules": true,
                        "paid": true,
                        "paidSupport": true,
                        "collaboration": true,
                        "allowChildOrgs": true,
                        "enterpriseEula": true,
                        "partners": ["acs", "analytics", "crittercism", "aca"]
                    }
                }
            ],
            "invites": [],
            "api_central": {
                "requested_user": "1d5b920d-7466-4357-ba07-586aeb3ec92e",
                "requested_date": "2018-09-21T15:09:04.027Z",
                "state": "requested",
                "provisioned": false,
                "url": null
            },
            "cloud_elements": {
                "requested_user": "f1e0b6ef-435e-438a-af47-c35300c5232f",
                "requested_date": "2019-01-31T15:53:22.394Z",
                "state": "requested",
                "provisioned": false,
                "url": null
            },
            "analytics": {
                "token": "6aa1a1801de28d4d"
            },
            "packageId": "54d8e4abce78815d81104cb4",
            "entitlements": {
                "apiRateMonth": 5000000000,
                "pushRateMonth": 8640000,
                "storageFilesGB": 100,
                "storageDatabaseGB": 100,
                "containerPoints": 4500,
                "arrowPublish": true,
                "eventRateMonth": 1000000000,
                "daysDataRetained": 731,
                "allowProduction": true,
                "appDesigner": true,
                "appPreview": true,
                "hyperloop": true,
                "nativeSDK": true,
                "premiumModules": true,
                "paid": true,
                "paidSupport": true,
                "collaboration": true,
                "allowChildOrgs": true,
                "enterpriseEula": true,
                "partners": ["acs", "analytics", "crittercism", "aca"],
                "_version": 1,
                "_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhcGlSYXRlTW9udGgiOjUwMDAwMDAwMDAsInB1c2hSYXRlTW9udGgiOjg2NDAwMDAsInN0b3JhZ2VGaWxlc0dCIjoxMDAsInN0b3JhZ2VEYXRhYmFzZUdCIjoxMDAsImNvbnRhaW5lclBvaW50cyI6NDUwMCwiYXJyb3dQdWJsaXNoIjp0cnVlLCJldmVudFJhdGVNb250aCI6MTAwMDAwMDAwMCwiZGF5c0RhdGFSZXRhaW5lZCI6NzMxLCJhbGxvd1Byb2R1Y3Rpb24iOnRydWUsImFwcERlc2lnbmVyIjp0cnVlLCJhcHBQcmV2aWV3Ijp0cnVlLCJoeXBlcmxvb3AiOnRydWUsIm5hdGl2ZVNESyI6dHJ1ZSwicHJlbWl1bU1vZHVsZXMiOnRydWUsInBhaWQiOnRydWUsInBhaWRTdXBwb3J0Ijp0cnVlLCJjb2xsYWJvcmF0aW9uIjp0cnVlLCJhbGxvd0NoaWxkT3JncyI6dHJ1ZSwiZW50ZXJwcmlzZUV1bGEiOnRydWUsInBhcnRuZXJzIjpbImFjcyIsImFuYWx5dGljcyIsImNyaXR0ZXJjaXNtIiwiYWNhIl0sIl92ZXJzaW9uIjoxfQ.MZOD6g3gpQlaV7O9_ap0RdWkqUqd5lEnuABfIPgda1s"
            }
        },
        "orgs": [{
                "name": "Appcelerator Staff",
                "org_id": 100000295,
                "guid": "aca22ab5-d281-43b4-b90d-5c0259da34da"
            },
            ...
        ],
        "user": {
            "_id": "5922b3fc999a9c36bdae27b2",
            "email": "yjin@axway.com",
            "user_id": null,
            "guid": "18c5902f-33eb-4aec-9dd9-681df30ec655",
            "firstname": "Yuping",
            "lastname": "Jin",
            "activated": true,
            "active": true,
            "created": "2017-05-22T09:48:44.647Z",
            "openid": "18c5902f-33eb-4aec-9dd9-681df30ec655",
            "updated": "2019-02-26T01:47:03.872Z",
            "account-confirm-date": "2017-05-22 09:57:34",
            "eula": {
                "enterprise": "1.5.1"
            },
            "logged_in_count": 14,
            "last_logged_in_org": 100000295,
            "last_browser_language": "en",
            "logged_in_from_web": true,
            "metadata": {},
            "prefs": {
                "firsttime": true,
                "notificationChecked": "2018-09-20T04:57:51.898Z"
            },
            "keepMeSignedIn": false,
            "axway_id": "a30fc5f9-dcbf-462a-b0a5-19bb64353f5e",
            "last_accessed_orgs": [{
                    "org_id": 100000424,
                    "date": "2018-09-20T04:51:28.520Z"
                },
                ...
            ],
            "oidc_org": 100000295,
            "login_org": "last_logged",
            "phone": "",
            "external": true,
            "disable_2fa": true,
            "is_staff": true
        },
        "role": "admin",
        "nodeacs": true
    }
}
*/
//
func authenticateByToken(m models.AuthModel) (*models.User, error) {

	accessToken := m.Password

	host360 := os.Getenv("DASHBOARD_HOST")
	if len(host360) == 0 {
		host360 = "https://platform-preprod.axwaytest.net"
	}
	sessionPath360 := os.Getenv("DASHBOARD_SESSPATH")
	if len(sessionPath360) == 0 {
		sessionPath360 = "/api/v1/auth/findSession"
	}

	authURL := host360 + sessionPath360

	// var host = Config.getConfiguration().getFeatureConfiguration('hostAppcelerator360');
	// var sessionPath = Config.getConfiguration().getFeatureConfiguration(FEATURE_AUTH_THRU_360).sessionPath;

	log.Debug("AuthenticateByToken - get session from dashboard at " + host360 + sessionPath360)

	client := http.Client{}

	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		log.Errorf("AuthenticateByToken: %v", err)
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)

	if err != nil {
		log.Errorf("AuthenticateByToken: %v", err)
		return nil, err
	}

	return checkAuthResponse(resp, accessToken)
}

// check the response of authentication request
func checkAuthResponse(resp *http.Response, accessToken string) (user *models.User, err error) {

	if resp.StatusCode != 200 {
		err = fmt.Errorf("failed to authenticate with token against dashboard. response code %v", resp.StatusCode)
		log.Errorf("checkAuthResponse: %v", err)
		return
	}

	bodyBuf, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Errorf("checkAuthResponse - failed to read response body. %v", err)
		return
	}

	jsonBody, err := gabs.ParseJSON(bodyBuf)
	if err != nil {
		log.Errorf("checkAuthResponse - failed to parse response body. %v", err)
		return
	}

	success := jsonBody.Path("success").Data().(bool)
	if !success {
		log.Error("checkAuthResponse - dashboard returns false for success field")
		err = errors.New("failed to authenticate with token against dashboard")
		return
	}

	sid := getSessionID(resp, jsonBody)
	if sid == "" {
		log.Error("checkAuthResponse - bad response from Appcelerator 360: no cookie info")
		err = errors.New("bad response from Appcelerator 360: no cookie info")
		return
	}

	user = createUserObject(jsonBody, sid, getDigest(accessToken))

	return
}

// get session ID from dashboard response when login successfully
func getSessionID(resp *http.Response, body *gabs.Container) string {

	// Look up connect.sid from cookie
	// < HTTP/1.1 200 OK
	// < Set-Cookie: org_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT
	// < Set-Cookie: guid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT
	// < Set-Cookie: org_id=100007996; Domain=.axwaytest.net; Path=/; Expires=Thu, 19 Mar 2020 08:17:26 GMT; HttpOnly
	// < Set-Cookie: guid=18c5902f-33eb-4aec-9dd9-681df30ec655; Domain=.axwaytest.net; Path=/; Expires=Thu, 19 Mar 2020 08:17:26 GMT; HttpOnly
	// < Set-Cookie: connect.sid=s%3AGHksGwZW38FNjFQDi0Et_6GFMNWxUnwd.d1Q9Ypg0LEvTWvcooeXlzKMDq9sklw%2BYwoi%2BSATektE; Domain=.axwaytest.net; Path=/; HttpOnly
	var cookies = resp.Header["Set-Cookie"]
	log.Debugf("Set-Cookie: %s", cookies)
	var sid string
	if cookies != nil {
		for _, cookie := range cookies {
			log.Debugf("a cookie: %s", cookie)
			if strings.Contains(cookie, "connect.sid=") {
				sid = strings.Split(strings.Split(cookie, ";")[0], "=")[1]
				log.Debugf("sid: %s", sid)
			}
		}
	}
	if sid == "" {
		// Now this is for testing only. It's been removed by dashboard.
		log.Debug("Sid is not found in the header try to get it from response body")
		if body.Path("result.connect_sid").Data() != nil {
			sid = body.Path("result.connect_sid").Data().(string)
		}
	}

	return sid
}

func authenticateByDOSAToken(m models.AuthModel) (*models.User, error) {

	log.Infof("verifying token against AxwayID...")
	accessToken := m.Password
	userContainer, err := verifyTokenByAxwayID(accessToken)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	userInfo := userContainer.Data().(map[string]interface{})

	log.Debugf("verified token successfully against AxwayID for user %s", userInfo["preferred_username"])
	return createUserForDOSA(userInfo, getDigest(accessToken))
}

func createUserForDOSA(userInfo map[string]interface{}, passwordHash string) (user *models.User, err error) {

	// {
	//     "sub":"745176bf-a2d1-4867-841f-60149434d765",
	//     "org_guid":"5e97b4d3-a859-4b02-848f-7797381e1de1",
	//     "email_verified":false,
	//     "environmentId":"17ba6ab9d0844dc3a92925ae1fbf288e",
	//     "sa_type":"DOSA",
	//     "preferred_username":"service-account-dosa_17ba6ab9d0844dc3a92925ae1fbf288e",
	//     "orgId":"300558949654437"
	// }

	user = &models.User{
		Username: userInfo["preferred_username"].(string),
		Password: passwordHash,
		Email:    userInfo["preferred_username"].(string),
		Realname: userInfo["preferred_username"].(string),
		Salt:     userInfo["orgId"].(string),
		Comment:  userTypeDOSA,
	}

	user.Rolename = roleNameDeveloper
	user.HasAdminRole = false
	user.Role = 2

	// use ResetUUID to store next time (last auth time + userSessionDur) for auth against backend again (ARS-4919)
	user.ResetUUID = time.Now().Add(userSessionDur).Format(time.RFC3339)

	return
}

// curl -v \
// -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUNXJfaUwwbWJXUWpFQS1JcWNDSkFKaXlia0k4V2xrUnd0YVFQV0ZlWjJJIn0.eyJqdGkiOiI0NDY5ZTQ4OC0yYjM5LTQ0YjQtODM2Yy1hMTI5NDI1OTMzY2QiLCJleHAiOjE1NTEyMzIwNzQsIm5iZiI6MCwiaWF0IjoxNTUxMjMwMjc0LCJpc3MiOiJodHRwczovL2xvZ2luLXByZXByb2QuYXh3YXkuY29tL2F1dGgvcmVhbG1zL0Jyb2tlciIsImF1ZCI6ImFtcGxpZnktY2xpIiwic3ViIjoiMThjNTkwMmYtMzNlYi00YWVjLTlkZDktNjgxZGYzMGVjNjU1IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYW1wbGlmeS1jbGkiLCJhdXRoX3RpbWUiOjE1NTEyMzAyNjEsInNlc3Npb25fc3RhdGUiOiJiYmFhYjFhNy0yMWZlLTRjZjYtYjllMS0xMjA4MDI0NmE0MDUiLCJhY3IiOiIwIiwiYWxsb3dlZC1vcmlnaW5zIjpbIiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiYWRtaW5pc3RyYXRvciIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYnJva2VyIjp7InJvbGVzIjpbInJlYWQtdG9rZW4iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sIm5hbWUiOiJZdXBpbmcgSmluIiwicHJlZmVycmVkX3VzZXJuYW1lIjoieWppbkBheHdheS5jb20iLCJnaXZlbl9uYW1lIjoiWXVwaW5nIiwiZmFtaWx5X25hbWUiOiJKaW4iLCJlbWFpbCI6InlqaW5AYXh3YXkuY29tIn0.Yr39yv4oOqcVs6-lnCQmlLdUr2kPxcV-3VNpJh74DIElVx5s-wkrNi6UKpqVA_k5nSfQskY2swD-aFi-_DObSImHxKCcCAXwIINYOAFpJPCLMnPTD9_x2hLsfVrgHkPvMtaGI0iofgbrDOBxvdzdbjj7qfpKqZ2aLjSZVJHMrGS3H2zDhBxaHTjMRRf8Ry6DFKPWkBZhFa8l8aqG52PbA-RAyP9_xgg0P-DUvFMhxsCrb73tne0DSr4jfp0otxrIpEKG_Eq-FZu-WGiHG052wxmATxYnCHYAE2zsvk7lWUOiL85AfMblz_4AJbdUUgZ_CdD7603h8JL6xZdFSD-tww" \
// https://login-preprod.axway.com/auth/realms/Broker/protocol/openid-connect/userinfo

// < HTTP/1.1 200 OK
// < Content-Type: application/json
// < Date: Wed, 27 Feb 2019 01:28:02 GMT
// < Content-Length: 171
// < Connection: keep-alive
// <
// * Connection #0 to host login-preprod.axway.com left intact
// {
//     "sub": "18c5902f-33eb-4aec-9dd9-681df30ec655",
//     "name": "Yuping Jin",
//     "preferred_username": "yjin@axway.com",
//     "given_name": "Yuping",
//     "family_name": "Jin",
//     "email": "yjin@axway.com"
// }

// < HTTP/1.1 401 Unauthorized
// < Content-Type: application/json
// < Date: Wed, 27 Feb 2019 01:30:55 GMT
// < Content-Length: 82
// < Connection: keep-alive
// <
// * Connection #0 to host login-preprod.axway.com left intact
// {
//     "error": "invalid_token",
//     "error_description": "Token invalid: Token is not active"
// }

// < HTTP/1.1 401 Unauthorized
// < Content-Type: application/json
// < Date: Wed, 27 Feb 2019 01:32:33 GMT
// < Content-Length: 82
// < Connection: keep-alive
// <
// * Connection #0 to host login-preprod.axway.com left intact
// {
//     "error": "invalid_token",
//     "error_description": "Token invalid: Failed to parse JWT"
// }
func verifyTokenByAxwayID(accessToken string) (*gabs.Container, error) {

	hostAxwayID := os.Getenv("AXWAYID_HOST")
	userInfoPathAID := os.Getenv("AXWAYID_USERINFOPATH")

	log.Debugf("verifyTokenByAxwayID - Verify access token against AxwayID at " + hostAxwayID + userInfoPathAID)
	authURL := hostAxwayID + userInfoPathAID

	client := http.Client{}

	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		log.Errorf("verifyTokenByAxwayID: %v", err)
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)

	if err != nil {
		log.Errorf("verifyTokenByAxwayID: %v", err)
		return nil, err
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("failed to verify token against AxwayID. response code %v", resp.StatusCode)
		log.Errorf("verifyTokenByAxwayID: %v", err)
		return nil, err
	}

	log.Debugf("verifyTokenByAxwayID - Verified through AxwayID successfully.")
	bodyBuf, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Errorf("verifyTokenByAxwayID - failed to read response body. %v", err)
		return nil, err
	}

	jsonBody, err := gabs.ParseJSON(bodyBuf)
	if err != nil {
		log.Errorf("verifyTokenByAxwayID - failed to parse response body. %v", err)
		return nil, err
	}

	return jsonBody, nil
}
