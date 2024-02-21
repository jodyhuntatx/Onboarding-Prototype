#!/usr/local/bin/python3

'''
 This is a utility that pulls info about active CyberArk platforms
 and renders it into a json format for onboarding support. 

 It takes an optional argument that names on older platform json file
 from which to copy searchpair values, thereby relieving the user of 
 manually re-entering them when recompiling the platforms.

 Raw json output is sent to stdout for further redirection to jq or file.
 Therefore DO NOT ADD PRINT STATEMENTS if you're piping this output to jq!!
 Use logging.info(msgs) instead.
'''

import requests
import json
import sys
import logging
from cybronboard import *

logfile = "./logs/compileplats.log"
loglevel = logging.INFO
logfmode = 'w'  			# w = overwrite, a = append

# MAIN ====================================================
logging.basicConfig(filename=logfile, encoding='utf-8', level=loglevel, filemode=logfmode)

# authenticate to CyberArk & add session token & subdomain to request
logging.info("Authenticating...")
admin_creds = getAuthnCreds()
resp_dict = authnCyberark(admin_creds)
errCheck(resp_dict)
logging.info("Successfully authenticated.")
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
  platsout[plat_id] = {}          # create dictionary entry named for platform ID
  platsout[plat_id]['id'] = plat_id
  platsout[plat_id]['systemtype'] = p['general']['systemType'].replace(" ","+")
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

# if filename of old platform listing provided, copy search_pairs into new
if len(sys.argv) > 1:
  old_platfile = sys.argv[1]
  with open(old_platfile) as f_in:
    old_plats = json.load(f_in)
  newplatsout = platsout.copy() # avoids changing dictionary while iterating
  for plat_id in platsout:
    old_plat = old_plats.get(plat_id,None)
    if old_plat is not None:
      newplatsout[plat_id]['searchpairs'] = old_plat['searchpairs']
  platsout = newplatsout

print(json.dumps(platsout))
