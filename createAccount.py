#!/usr/local/bin/python3

import json
import sys
import requests
import urllib.parse

import logging
logfile="./logs/createAccount.log"
loglevel = logging.DEBUG
logfmode = 'w'  # w = overwrite, a = append
logging.basicConfig(filename=logfile, encoding='utf-8', level=loglevel, filemode=logfmode)

# unmarshal provisioning request parameter, replace + with space
prov_req = json.loads(sys.argv[1].replace("+"," "))

# load platform dictionary
platfile="./platforms.json"
with open(platfile) as f_in:
  platforms = json.load(f_in)

# Extract HTTPS values
cybr_subdomain = prov_req["cybr_subdomain"]
session_token = prov_req["session_token"]
platform_id = prov_req["platform_id"]

status_code = 201
response_body = f"Account created successfully."

# Construct account request from values in provisioning request
acct_props = prov_req["values"]
account_req = {
    "safeName": prov_req["safe_name"],
    "platformID": prov_req["platform_id"]
}
# add required properties to account_request
reqs_plat_props = platforms[platform_id]["required"]
for key, val in acct_props.items():
    if key.upper() in reqs_plat_props:
        account_req[key] = acct_props[key]

# secret and username are optional, but are not platformAccountProperties
secret = acct_props.get("secret",None)
if secret is not None:
    # hardcode password type for now - need to revisit for key type
    account_req["secretType"] = "password"  
    account_req["secret"] = secret
    acct_props.pop("secret")
username = acct_props.get("username",None)
if username is not None:
    account_req["username"] = username 
    acct_props.pop("username")

account_req["secretManagement"] = {
    "automaticManagementEnabled": True
}
# add optional values to account properties
account_req["platformAccountProperties"] = {}
for key, val in acct_props.items():
    if key.upper() not in reqs_plat_props:
        account_req["platformAccountProperties"][key] = acct_props[key]

logging.debug(f"account_req: {account_req}")

url = f"https://{cybr_subdomain}.privilegecloud.cyberark.cloud/passwordvault/api/accounts"
payload = json.dumps(account_req)
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {session_token}",
}
response = requests.request("POST", url, headers=headers, data=payload)
status_code = response.status_code
logging.debug(response.text)
if status_code != 201:
    if response.status_code == 409:
        status_code = 409
        response_body = "Account with that name already exists."
    else:
        response_body = "Invalid request format."
        logging.debug(response_body)
        logging.debug(response.text)

logging.debug("================ createAccount() ================")
logging.debug(f"\turl: {url}\n\tpayload: {payload}")
logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

return_dict = {}
return_dict["status_code"] = status_code
return_dict["response_body"] = response_body
print(return_dict)