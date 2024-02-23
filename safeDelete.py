#!/usr/local/bin/python3

import json
import sys
import logging
from cybronboard import *

logfile = "./logs/safeDelete.log"
loglevel = logging.DEBUG           # BEWARE: DEBUG loglevel can leak secrets!
logfmode = 'w'  		              # w = overwrite, a = append

# MAIN =================================================
logging.basicConfig(filename=logfile, encoding='utf-8', level=loglevel, filemode=logfmode)

# Get provisioning request from single filename argument
try:
  reqfile = sys.argv[1]
  with open(reqfile) as f_in:
    prov_req = json.load(f_in)
except IOError:
    err_msg = f"{sys.argv[0]}: Could not read provisioning request from filename argument."
    print(err_msg)
    logging.error(err_msg)
    sys.exit(-1)

# Generate safe name based on provisioning request values, add to provisioning request
print("Generating safe name...")
resp_dict = getSafeName(prov_req)
errCheck(resp_dict)
logging.info(f"safe_name: {resp_dict['safe_name']}")
prov_req["safe_name"] = resp_dict["safe_name"]

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

print("Deleting safe...")
resp_dict = deleteSafe(prov_req)
errCheck(resp_dict, expected=[204])
logging.info(f"safe_name: {prov_req['safe_name']} no longer exists.")

sys.exit(0)