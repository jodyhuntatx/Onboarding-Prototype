#!/usr/local/bin/python3

import json
import sys
import requests
import urllib.parse

import logging
logfile="./logs/authnCyberArk.log"
loglevel = logging.INFO  # WARNING: level DEBUG leaks admin creds in log
logfmode = 'w'  # w = overwrite, a = append
logging.basicConfig(filename=logfile, encoding='utf-8', level=loglevel, filemode=logfmode)

# -------------------------------------------
def urlify(s):
    # URL encodes a given string
    return urllib.parse.quote(s)
# -------------------------------------------

admin_dict = json.loads(sys.argv[1])
cybr_subdomain = admin_dict["cybr_subdomain"]
cybr_username = admin_dict["cybr_username"]
cybr_password = admin_dict["cybr_password"]

# uses Pcloud creds to authenticate to CyberArk Identity
# returns session_token (CyberArk Identity JWT) to use in further CyberArk API calls

session_token = None
status_code = 200
response_body = "Successfully authenticated to CyberArk Privilege Cloud."

# Authenticate to CyberArk Identity
url = f"https://{cybr_subdomain}.cyberark.cloud/api/idadmin/oauth2/platformtoken"
payload = f"grant_type=client_credentials&client_id={urlify(cybr_username)}&client_secret={urlify(cybr_password)}"
headers = {"Content-Type": "application/x-www-form-urlencoded"}
response = requests.request("POST", url, headers=headers, data=payload)
if response.status_code == 200:
    # Parse the JSON response into a dictionary
    data = response.json()
    # Extract session token from the response dict
    session_token = data.get("access_token", None)
    if session_token is None:
        status_code = 401
        response_body = json.dumps(
            f"There was a problem authenticating to: {cybr_subdomain}.privilegecloud.cyberark.cloud"
        )
else:
    status_code = 500
    response_body = json.dumps(
        f"There was a problem authenticating to: {cybr_subdomain}.privilegecloud.cyberark.cloud"
    )

logging.debug("================ authnCyberark() ================")
logging.debug(f"\turl: {url}\n\tstatus_code: {status_code}\n\tpayload: {payload}\n\tresponse: {response_body}")

return_dict = {}
return_dict["status_code"] = status_code
return_dict["response_body"] = response_body
return_dict["session_token"] = session_token
print(return_dict)
