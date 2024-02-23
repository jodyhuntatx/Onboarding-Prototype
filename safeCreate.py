#!/usr/local/bin/python3

import json
import sys
import logging
from cybronboard import *

logfile = "./logs/safeCreate.log"
loglevel = logging.INFO       # BEWARE! DEBUG loglevel can leak secrets!
logfmode = 'w'                # w = overwrite, a = append

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

print(f"Creating safe...")
resp_dict = createSafe(prov_req)
errCheck(resp_dict, expected=[201,409])
logging.info(f"safe_name: {prov_req['safe_name']} was created or already exists.")

print("Adding members...")
resp_dict = addSafeMembers(prov_req)
errCheck(resp_dict, expected=[201,409])
logging.info(f"{prov_req['safeAdmins']}, {prov_req['safeFullUsers']} and {prov_req['syncMembers']} are members of safe {prov_req['safe_name']}")

sys.exit(0)