#!/usr/local/bin/python3

import subprocess
import json
import sys
import os

import logging
logfile = "./logs/onboard.log"
loglevel = logging.INFO
logfmode = 'w'  # w = overwrite, a = append
logging.basicConfig(filename=logfile, encoding='utf-8', level=loglevel, filemode=logfmode)

#====================================================
# Constants
reqfile = "./provreq.json"

#====================================================
# Functions for calling python scripts as functions
def marshal(dict):
    return str(dict).replace(" ", "").replace("'", '"')

def unmarshal(procout):
    return json.loads(procout.stdout.decode().replace("'", '"'))

def callFunction(funcName, input_dict, success_codes):
  procout = subprocess.run([funcName, marshal(input_dict)], stdout=subprocess.PIPE)
  resp_dict = unmarshal(procout)
  logging.debug(f"{funcName}:\n\t\t{resp_dict}")
  if resp_dict["status_code"] not in success_codes:
    logging.error(resp_dict["response_body"])
    logging.error(f"Exiting due to error. See {funcName} logfile for more details.")
    sys.exit(0)
  return resp_dict

#====================================================
# MAIN

# Get provisioning request
with open(reqfile) as f_in:
  prov_req = json.load(f_in)

# Authenticate to CyberArk Identity
admin_creds = {
    "cybr_subdomain": os.environ.get("CYBR_SUBDOMAIN",None),
    "cybr_username": os.environ.get("CYBR_USERNAME",None),
    "cybr_password": os.environ.get("CYBR_PASSWORD",None),
}
# Validate all creds have a value, if not exit
none_keys = [key for key, value in admin_creds.items() if value is None]
if none_keys:
  print("Missing one of CYBR_SUBDOMAIN, CYBR_USERNAME, CYBR_PASSWORD environment variables.")
  sys.exit(-1)

resp_dict = callFunction("./authnCyberArk.py", admin_creds, [200])
prov_req["session_token"] = resp_dict["session_token"]
prov_req["cybr_subdomain"] = admin_creds["cybr_subdomain"]

# Determine plaform ID based on provisioning request values
resp_dict = callFunction("./getPlatform.py", prov_req, [200])
prov_req["platform_id"] = resp_dict["platform_id"]
logging.info(f"platform_id: {prov_req['platform_id']}")

# Generate safe name based on provisioning request values
resp_dict = callFunction("./getSafeName.py", prov_req, [200])
prov_req["safe_name"] = resp_dict["safe_name"]
logging.info(f"safe_name: {prov_req['safe_name']}")

'''
# Delete safe
resp_dict = callFunction("./deleteSafe.py", prov_req, [204])
logging.info(f"safe_name: {prov_req['safe_name']}")
sys.exit(0)
'''

# Create safe
resp_dict = callFunction("./createSafe.py", prov_req, [201,409])
logging.info(f"safe_name: {prov_req['safe_name']} was created or already exists.")

# Add members to safe
resp_dict = callFunction("./addSafeMembers.py", prov_req, [201,409])
logging.info(f"{prov_req['safeAdmins']}, {prov_req['safeFullUsers']} and {prov_req['syncMembers']} are now members of safe {prov_req['safe_name']}")

# Create account
resp_dict = callFunction("./createAccount.py", prov_req, [201,409])
logging.info(f"Account now exists in safe {prov_req['safe_name']}")