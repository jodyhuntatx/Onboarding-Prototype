#!/usr/local/bin/python3

import subprocess
import requests
import json
import sys

import logging
logfile = "./logs/compileplats.log"
loglevel = logging.INFO
logfmode = 'w'  # w = overwrite, a = append
logging.basicConfig(filename=logfile, encoding='utf-8', level=loglevel, filemode=logfmode)

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
    logging.error(f"Exiting due to error. See {funcName} logfile for details.")
    sys.exit(0)
  return resp_dict

#====================================================
# MAIN

# Authenticate to CyberArk Identity
admin_creds = {
    "cybr_subdomain": "cybr-secrets",
    "cybr_username": "jody_bot@cyberark.cloud.3357",
    "cybr_password": "CyberArk11@@",
}

resp_dict = callFunction("./authnCyberArk.py", admin_creds, [200])
session_token = resp_dict["session_token"]
cybr_subdomain = admin_creds["cybr_subdomain"]

url = f"https://{cybr_subdomain}.privilegecloud.cyberark.cloud/passwordvault/api/platforms?active=true"
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {session_token}",
}
response = requests.request("GET", url, headers=headers)
if response.status_code == 200:
    # Parse the JSON response into a dictionary
    plat_data = response.json()

plats = plat_data["Platforms"]
platsout = {}
for p in plats:
  plat_id = p['general']['id']
  platsout[plat_id] = {}
  platsout[plat_id]['id'] = plat_id
  platsout[plat_id]['searchpairs'] = {}
  platsout[plat_id]['required'] = []
  platsout[plat_id]['allkeys'] = ['SECRET']
  for reqd in p['properties']['required']:
    prop_name = reqd['name'].upper()
    platsout[plat_id]['required'].append(prop_name)
    platsout[plat_id]['allkeys'].append(prop_name)
  for optl in p['properties']['optional']:
    prop_name = optl['name'].upper()
    platsout[plat_id]['allkeys'].append(prop_name)
print(json.dumps(platsout))
  
