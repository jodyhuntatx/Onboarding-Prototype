#!/usr/local/bin/python3
import subprocess
import json
import sys

import logging
logfile="./logs/getSafeName.log"
loglevel = logging.DEBUG
logfmode = 'w'  # w = overwrite, a = append
logging.basicConfig(filename=logfile, encoding='utf-8', level=loglevel, filemode=logfmode)

# generates safe name base on provisioning record values
# - platform: AWS,AZR,GCP,ONP
# - billcode
# - type: DB,SVR,SVC
# - subtype: MYS,MSQ,PSQ,MDB,ORC
# - env: DEV,TST,UAT,PRD
# - approval: APR,NAP

# unmarshal provisioning request parameter, replace + with space
prov_req = json.loads(sys.argv[1].replace("+"," "))

# TO BE COMPLETED: Currently only returns first 3 text chars of input in uppercase
# Encoding functions for each positional argument
def enc_platform(inp):
  return inp[0:3].upper()

def enc_billcode(inp):
  return inp

def enc_env(inp):
  return inp[0:3].upper()

def enc_type(inp):
  return inp[0:3].upper()

def enc_subtype(inp):
  return inp[0:3].upper()

def enc_approval(inp):
  return inp[0:3].upper()

# Dispatch table
dispatch = {
    0: enc_platform,
    1: enc_billcode,
    2: enc_type,
    3: enc_subtype,
    4: enc_env,
    5: enc_approval
}

input_keys = ["platform","billcode","type","subtype","env","apprReq"]
input_vals = []
for i in range(len(input_keys)):
  input_vals.append(prov_req[input_keys[i]])

safe_name = ""
for i in range(0,len(input_vals)):
  if safe_name != "":
    safe_name += "-"
  safe_name += dispatch[i](input_vals[i])

status_code = 200
response_body = "Safe name generated."

logging.debug("================ getSafeName() ================")
logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

return_dict = {}
return_dict["status_code"] = status_code
return_dict["response_body"] = response_body
return_dict["safe_name"] = safe_name
print(return_dict)
