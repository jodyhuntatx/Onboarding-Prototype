#!/usr/local/bin/python3

import json
import sys
import logging
from cybronboard import *
from src.getSHFilterForSafe import getSHFilterForSafe
from src.getSHSyncPolicy import getSHSyncPolicy

logfile = "./logs/getSHInfo.log"
loglevel = logging.INFO      # BEWARE! DEBUG loglevel can leak secrets!
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

# Generate safe name based on provisioning request values, add to provisioning request
print("Generating safe name...")
resp_dict = getSafeName(prov_req)
errCheck(resp_dict)
logging.info(f"safe_name: {resp_dict['safe_name']}")
prov_req["safe_name"] = resp_dict["safe_name"]

# authenticate to CyberArk & add session token & subdomain to request
print("Authenticating...")
admin_creds = getAuthnCreds()
resp_dict = authnCyberark(admin_creds)
errCheck(resp_dict)
logging.info(resp_dict["response_body"])
prov_req["session_token"] = resp_dict["session_token"]
prov_req["cybr_subdomain"] = admin_creds["cybr_subdomain"]

# Get SecretsHub source store ID, add to provisioning request
print("Getting SecretsHub source store ID...")
resp_dict = getSHSourceStoreId(prov_req)
errCheck(resp_dict)
logging.info(resp_dict["response_body"])
prov_req["source_store_id"] = resp_dict["store_id"]
print("Source store ID: ", prov_req["source_store_id"])

# Get SecretsHub target store ID, add to provisioning request
print("Getting SecretsHub target store ID...")
resp_dict = getSHTargetStoreId(prov_req)
errCheck(resp_dict)
logging.info(resp_dict["response_body"])
prov_req["target_store_id"] = resp_dict["store_id"]
print("Target store ID: ", prov_req["target_store_id"])

# Get SecretsHub filter ID, add to provisioning request
print("Getting SecretsHub filter ID...")
resp_dict = getSHFilterForSafe(prov_req)
errCheck(resp_dict)
logging.info(resp_dict["response_body"])
prov_req["filter_id"] = resp_dict["filter_id"]
print("Safe filter ID: ", prov_req["filter_id"])

# Get SecretsHub sync policy ID, add to provisioning request
print("Getting SecretsHub sync policy ID...")
resp_dict = getSHSyncPolicy(prov_req)
errCheck(resp_dict)
logging.info(resp_dict["response_body"])
prov_req["policy_id"] = resp_dict["policy_id"]
print("Sync policy ID: ", prov_req["policy_id"])

sys.exit(0)