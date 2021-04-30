package ars

import (
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"

	"github.com/Jeffail/gabs"
	"github.com/goharbor/harbor/src/common/utils/log"
)

type Org struct {
	ID       string
	Name     string
	Admin    bool
	ARSAdmin bool
}

// Get organization information for user from dashboard
func getAndVerifyOrgInfoFrom360(username, sid string) (haveAccess bool, orgs map[string]Org, err error) {

	// reqTimeout := 20000; //20s

	//curl -i -b connect.sid=s%3AaJaL7IWQ_cDvmVBeQRY997hf.vVzLV2aFvrYiEKmfdTARTuHessesQ0Xm87JvFESaus http://dashboard.appcelerator.com/api/v1/user/organizations
	/*
	   response for invalid session
	   HTTP/1.1 401 Unauthorized
	   X-Frame-Options: SAMEORIGIN
	   Cache-Control: no-cache, max-age=0, must-revalidate
	   Pragma: no-cache
	   Vary: Accept-Encoding
	   Access-Control-Allow-Origin: *
	   Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE
	   Access-Control-Allow-Headers: Content-Type, api_key
	   Content-Type: application/json; charset=utf-8
	   Content-Length: 59
	   Set-Cookie: connect.sid=s%3AIEpzWmzs4MQJGJMEcLmjlZm_.Cyi4LlO8gP%2B4sPHR0bdEGqjiqjuW3RJlZe6O2bt8QkI; Domain=dashboard.appcelerator.com; Path=/; Expires=Sat, 12 Apr 2014 13:04:07 GMT; HttpOnly; Secure
	   Date: Thu, 13 Mar 2014 13:04:07 GMT
	   Connection: close

	   {"success":false,"description":"Login Required","code":401}
	*/

	host360 := os.Getenv("DASHBOARD_HOST")
	if len(host360) == 0 {
		host360 = "https://platform-preprod.axwaytest.net"
	}
	orgInfoPath360 := os.Getenv("DASHBOARD_ORGINFOPATH")
	if len(orgInfoPath360) == 0 {
		orgInfoPath360 = "/api/v1/user/organizations"
	}

	orgInfoURL := host360 + orgInfoPath360

	log.Debugf("Get user organization information for %s from %s", username, orgInfoURL)
	log.Debugf("dashboard session ID: %s ", sid)

	//https://webcache.googleusercontent.com/search?q=cache:OVK76hrG4T8J:https://medium.com/%40nate510/don-t-use-go-s-default-http-client-4804cb19f779+&cd=4&hl=en&ct=clnk&gl=jp
	client := http.Client{}

	req, err := http.NewRequest("GET", orgInfoURL, nil)

	req.Header.Add("Cookie", "connect.sid="+sid)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)

	if err != nil {
		log.Errorf("Failed to get organization info from dashboard. %v", err)
		return
	}

	if resp.StatusCode == 401 {
		log.Warning("getAndVerifyOrgInfoFrom360 - Failed to get organization information. Session is invalid")
		err = errors.New("Failed to get organization information. Session is invalid.")
		return
	}

	if resp.StatusCode != 200 {
		log.Debugf("dashboard returns status %s", resp.Status)
		err = errors.New("Failed to get organization info")
		return
	}

	bodyBuf, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Errorf("Failed to read response body. %v", err)
		return
	}

	jsonBody, err := gabs.ParseJSON(bodyBuf)
	if err != nil {
		log.Errorf("Failed to parse response body %s. %v", string(bodyBuf), err)
		return
	}

	success := jsonBody.Path("success").Data().(bool)
	if !success {
		log.Error("dashboard returns false for success field")
		err = errors.New("Failed to get organization info")
		return
	}

	/*
		     {
			     "success": true,
			     "result": [{
				     "_id": "51c40b4497a98c6046000002",
				     "org_id": 14301,
				     "name": "Appcelerator, Inc",
				     "guid": "64310644-794b-c8d0-a8b8-0a373d20dabc",
				     "user_count": 97,
				     "current_users_role": "normal",
				     "is_node_acs_admin": false,
				     "trial_end_date": "",
				     "created": "2012-01-11 10:58:09.0",
				     "reseller": false,
				     "active": true,
				     "envs": [{
				     "_id": "production",
				     "name": "production",
				     "isProduction": true,
				     "acsBaseUrl": "https://preprod-api.cloud.appcelerator.com",
				     "acsAuthBaseUrl": "https://dolphin-secure-identity.cloud.appcelerator.com",
				     "nodeACSEndpoint": "https://admin.cloudapp-enterprise-preprod.appcelerator.com"
			     }, {
				     "_id": "development",
				     "name": "development",
				     "isProduction": false,
				     "acsBaseUrl": "https://preprod-api.cloud.appcelerator.com",
				     "acsAuthBaseUrl": "https://dolphin-secure-identity.cloud.appcelerator.com",
				     "nodeACSEndpoint": "https://admin.cloudapp-enterprise-preprod.appcelerator.com"
			     }],
			     "parent_org_guid": ""
			     }]
		     }
	*/

	organizations := jsonBody.Path("result").Data().([]interface{})
	if !validateOrgs(organizations) {
		log.Errorf("getAndVerifyOrgInfoFrom360 - Bad response from dashboard: invalid organization info. %v", organizations)
		err = errors.New("Bad response from dashboard")
		return
		//TODO send mail
	}

	//check if the user's organizations have access to current deployment (identified by admin host)
	orgs, haveAccess = checkOrgs(organizations)
	return

}

// haveAccess: If the user has access to the current cluster.
func checkOrgs(orgArray []interface{}) (orgs map[string]Org, haveAccess bool) {

	re := regexp.MustCompile("^(http|https)://") //https://golang.org/pkg/regexp/#MustCompile
	thisEnvAdminURL := os.Getenv("ADMIN_URL")
	thisEnv2ndAdminURL := os.Getenv("APPC_ADMIN_URL")
	thisEnvHost := re.ReplaceAllString(thisEnvAdminURL, "")
	thisEnv2ndHost := re.ReplaceAllString(thisEnv2ndAdminURL, "")

	log.Debugf("check if user's organizations have access to this domain: %s and %s", thisEnvHost, thisEnv2ndHost)

	orgs = map[string]Org{} //organizations which can access this domain (deployment)
	userOrgIds := []string{}

	for _, orgData := range orgArray {

		orgDoc := orgData.(map[string]interface{})
		orgToSave := Org{
			Name:     orgDoc["name"].(string),
			ARSAdmin: false,
		}

		orgId := orgDoc["org_id"]
		switch v := orgId.(type) {
		default:
			log.Errorf("unexpected type of org ID: %T", v)
			continue
		case float64:
			orgToSave.ID = strconv.FormatFloat(orgId.(float64), 'f', -1, 64)
		case string:
			orgToSave.ID = orgId.(string)
		}

		if orgDoc["current_users_role"] != nil && orgDoc["current_users_role"].(string) == "admin" {
			orgToSave.Admin = true
		} else {
			orgToSave.Admin = false
		}

		if orgDoc["is_node_acs_admin"] != nil {
			orgToSave.ARSAdmin = orgDoc["is_node_acs_admin"].(bool)
		}

		userOrgIds = append(userOrgIds, orgToSave.ID)

		//check if the org has access to this domain (deployment)
		//if yes save it in "orgs"
		if envsData, ok := orgDoc["envs"]; ok {
			envs := envsData.([]interface{})
			for _, envData := range envs {
				env := envData.(map[string]interface{})
				adminHost, hok := env["nodeACSEndpoint"].(string)
				if hok {
					re := regexp.MustCompile("^(http|https)://")
					adminHost := re.ReplaceAllString(adminHost, "")
					log.Debugf("org %s(%s) have access to %s", orgToSave.Name, orgToSave.ID, adminHost)
					if adminHost == thisEnvHost || adminHost == thisEnv2ndHost {
						orgs[orgToSave.ID] = orgToSave
						break
					}
				}
			}
		}
	}

	if len(orgs) < 1 {
		log.Errorf("getAndVerifyOrgInfoFrom360 - User's organization(s) %v doesn't have access to current deployment (%s).", userOrgIds, thisEnvHost)
		haveAccess = false
		return
	}

	haveAccess = true
	return
}

/**
 * Validate the organization info got from 360 for a user is valid.
 * @param orgArray
 * @returns {boolean}
 */
func validateOrgs(orgArray []interface{}) bool {

	if len(orgArray) == 0 {
		return false
	}

	for _, orgData := range orgArray {
		orgDoc := orgData.(map[string]interface{})

		if _, ok := orgDoc["org_id"]; !ok {
			return false
		}
		if _, ok := orgDoc["name"]; !ok {
			return false
		}
		if _, ok := orgDoc["is_node_acs_admin"]; !ok {
			return false
		}
	}
	return true
}
