#!/usr/local/bin/python3

import json
import sys
import requests
import urllib.parse

import logging
logfile = "./logs/deleteAccount.log"
loglevel = logging.DEBUG
logfmode = "w"  # w = overwrite, a = append
logging.basicConfig(
    filename=logfile, encoding="utf-8", level=loglevel, filemode=logfmode
)

# Unmarshal provisioning request
prov_req = json.loads(sys.argv[1]).replace("+"," ")

# Extract HTTPS values
cybr_subdomain = prov_req["cybr_subdomain"]
session_token = prov_req["session_token"]

url = (
    f"https://{cybr_subdomain}.privilegecloud.cyberark.cloud/passwordvault/api/accounts"
)
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {session_token}",
}
search_url = url + f"?search={secret_id}"
response = requests.request("get", search_url, headers=headers)
status_code = response.status_code
response_body = response.text
if status_code == 200:
    account_dict = json.loads(response.text)
    num_found = account_dict["count"]
    match num_found:
        case 1:
            account_id = account_dict["value"][0]["id"]
            account_name = account_dict["value"][0]["name"]
            safe_name = account_dict["value"][0]["safeName"]
            delete_url = url + f"/{account_id}"
            response = requests.request("delete", delete_url, headers=headers)
            status_code = response.status_code
            if status_code == 204:
                response_body = (
                    f"Account {account_name} in safe {safe_name} deleted successfully."
                )
            else:
                response_body = response.text
        case 0:
            status_code = 404
            response_body = f"No account found for secret_id: {secret_id}"
        case _:
            status_code = 409  # 409 == 'conflict'
            response_body = f"More than one account found for secret_id: {secret_id}"
else:
    response_body = (
        f"Error searching for account corresponding to secret_id: {secret_id}"
    )

logging.debug("================ deleteAccount() ================")
logging.debug(f"\tsecret_id: {secret_id}")
logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

return_dict = {}
return_dict["status_code"] = status_code
return_dict["response_body"] = response_body
print(return_dict)
