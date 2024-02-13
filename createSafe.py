#!/usr/local/bin/python3

# CreateSafe(safe_dict)

import json
import sys
import requests

import logging
logfile = "./logs/createSafe.log"
loglevel = logging.DEBUG
logfmode = "w"  # w = overwrite, a = append
logging.basicConfig(
    filename=logfile, encoding="utf-8", level=loglevel, filemode=logfmode
)

# unmarshal provisioning request parameter, replace + with space
prov_req = json.loads(sys.argv[1].replace("+"," "))

cybr_subdomain = prov_req["cybr_subdomain"]
session_token = prov_req["session_token"]
safe_name = prov_req["safe_name"]
safe_req = {
    "safeName": safe_name,
    "description": "Created by CybrOnboarding engine.",
    "olacEnabled": "False",
    "managingCPM": "",
    "numberOfDaysRetention": 0,
}

status_code = 201
response_body = f"Safe {safe_name} created successfully."

url = f"https://{cybr_subdomain}.privilegecloud.cyberark.cloud/passwordvault/api/safes"
payload = json.dumps(safe_req)
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {session_token}",
}
response = requests.request("POST", url, headers=headers, data=payload)
status_code = response.status_code
if status_code != 201:
    if status_code == 409:
        response_body = f"Safe {safe_name} already exists."
    else:
        status_code = 500
        response_body = f"Unknown error creating safe {safe_name}."
        logging.debug(response_body)
        logging.debug(response.text)

logging.debug("================ createSafe() ================")
logging.debug(f"status_code: {status_code}\n\tresponse: {response_body}")

return_dict = {}
return_dict["status_code"] = status_code
return_dict["response_body"] = response_body
print(return_dict)