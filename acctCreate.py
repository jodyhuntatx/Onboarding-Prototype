#!/usr/local/bin/python3

import json
import sys
import logging
from cybronboard import *

logfile = "./logs/accountCreate.log"
loglevel = logging.INFO          # BEWARE: DEBUG loglevel might leak secrets!
logfmode = 'w'  		              # w = overwrite, a = append

# MAIN =================================================
logging.basicConfig(filename=logfile, encoding='utf-8', level=loglevel, filemode=logfmode)

# Get provisioning request from single filename argument
try:
  if len(sys.argv) != 2:
    raise IOError
  reqfile = sys.argv[1]
  with open(reqfile) as f_in:
    prov_req = json.load(f_in)
except IOError:
    err_msg = f"{sys.argv[0]}: Could not read provisioning request from filename argument."
    print(err_msg)
    logging.error(err_msg)
    sys.exit(-1)

print("Determining platform ID based on provisioning request values...")
resp_dict = getPlatformId(prov_req)
errCheck(resp_dict)
logging.info(f"platform_id: {resp_dict['platform_id']}")
prov_req["platform_id"] = resp_dict["platform_id"]

print("Validating request account properties with platform properties...")
resp_dict = validateRequestWithPlatform(prov_req)
errCheck(resp_dict)
logging.info(f"Request validated with platform.")

print("Generating safe name based on provisioning request values...")
resp_dict = getSafeName(prov_req)
errCheck(resp_dict)
prov_req["safe_name"] = resp_dict["safe_name"]
logging.info(f"safe_name: {resp_dict['safe_name']}")

print("Getting admin creds...")
resp_dict = getAuthnCreds()
errCheck(resp_dict)
admin_creds = resp_dict["admin_creds"]

print("Authenticating...")
resp_dict = authnCyberark(admin_creds)
errCheck(resp_dict)
logging.info("Successfully authenticated.")
prov_req["session_token"] = resp_dict["session_token"]
prov_req["cybr_subdomain"] = admin_creds["cybr_subdomain"]

print(f"Creating account...")
resp_dict = createAccount(prov_req)
errCheck(resp_dict, expected=[201,409])
logging.info("Account exists in safe.")

sys.exit(0)