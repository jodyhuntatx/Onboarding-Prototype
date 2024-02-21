
#############################################################################
#############################################################################
# getSafeName.py

import json
import logging

# Generates safe name base on provisioning record values.

# Safe name format as implemented: PLT-BILLCODE-ENV-APP
# - platform: AWS,AZR,GCP,ONP
# - billcode: verbatim
# - env: DEV,TST,UAT,PRD
# - approval: APR,NAP

def getSafeName(prov_req):

  with open("./json/safenamerules.json") as sr:
      saferules = json.load(sr)

  # MAIN ========================================================
  # If above functions and data structures are correct, 
  #   there should be no need to edit below this line

  logging.debug("================ getSafeName() ================")
  status_code = 200
  response_body = "Safe name generated."
  safe_name = ""

  # names of keys in request from which to compose safe name
  input_keys = [ r["keyname"] for r in saferules ]
  input_vals = []
  # first ensure we have input values for each required input_key
  for idx in range(len(input_keys)):
    input_val = prov_req.get(input_keys[idx],None)
    if input_val is not None:
      input_vals.append(input_val)
    else:
      status_code = 400
      err_msg = f"Missing key required for safe naming: {input_keys[idx]}"
      logging.error(err_msg)
      response_body = err_msg

  if status_code == 200:
    for rule in saferules:
        keyval = prov_req[rule["keyname"]]
        outval = None
        match rule["maptype"]:
            case "valuemap":
                for vmap in rule["valuemap"]:
                    upvals = [v.upper() for v in vmap["inputs"]]
                    if str(keyval).upper() in upvals:
                        outval = vmap["output"].upper()
                        break
            case "literal":
                outval = str(keyval).upper()
            case "substring":
                beg = rule["substring"]["start"]
                if beg > len(str(keyval)):
                  beg = 0
                end = rule["substring"]["end"]
                if end > len(str(keyval)):
                  end = len(str(keyval))
                outval = str(keyval)[beg:end].upper()
            case _:
                logging.error(f"Invalid maptype: {rule['maptype']}")

        if outval is not None:
            if safe_name != "":
                safe_name += "-"
            safe_name += outval
        else:
            status_code = 400
            err_msg = f"No safename mapping rule found for {keyval}"
            logging.error(err_msg)
            response_body = err_msg
            break

  logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

  return_dict = {}
  return_dict["status_code"] = status_code
  return_dict["response_body"] = response_body
  return_dict["safe_name"] = safe_name
  return return_dict
