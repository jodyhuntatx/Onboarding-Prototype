
#############################################################################
#############################################################################
# getSafeName.py

import logging

# Generates safe name base on provisioning record values.

# Safe name format as implemented: PLT-BILLCODE-ENV-APP
# - platform: AWS,AZR,GCP,ONP
# - billcode: verbatim
# - env: DEV,TST,UAT,PRD
# - approval: APR,NAP

def getSafeName(prov_req):

  # Encoding functions for each component of safe name
  def enc_platform(inp):
    match inp.upper():
      case "AWS" | "AMAZON":
        return "AWS"
      case "AZR" | "AZURE":
        return "AZR"
      case "GCP" | "GOOGLE":
        return "GCP"
      case "ONP" | "ONPREM":
        return "ONP"
      case _:
        logging.error(f"No encoding rule for platform value {inp}.")
        return None

  def enc_billcode(inp):
    return str(inp)

  def enc_env(inp):
    match inp.upper():
      case "DEV" | "DEVELOPMENT":
        return "DEV"
      case "TST" | "TEST":
        return "TST"
      case "UAT" | "ACCEPTANCE":
        return "UAT"
      case "PRD" | "PRODUCTION":
        return "PRD"
      case _:
        logging.error(f"No encoding rule for environment value {inp}.")
        return None

  def enc_approval(inp):
    match inp.upper():
      case "T" | "TRUE":
        return "APR"
      case "F" | "FALSE":
        return "NAP"
      case _:
        logging.error(f"No encoding rule for approval required value {inp}.")
        return None

  # Dispatch table - ordered per safename field order
  dispatch = {
      0: enc_platform,
      1: enc_billcode,
      2: enc_env,
      3: enc_approval
  }

  # names of keys in request from which to compose safe name
  input_keys = ["platform","billcode","env","apprReqd"]

  # MAIN ========================================================
  # If above functions and data structures are correct, 
  #   there should be no need to edit below this line

  logging.debug("================ getSafeName() ================")
  status_code = 200
  response_body = "Safe name generated."
  safe_name = ""

  input_vals = []
  # first ensure we have input values for each required input_key
  for idx in range(len(input_keys)):
    input_val = prov_req.get(input_keys[idx],None)
    if input_val is not None:
      input_vals.append(input_val)
    else:
      status_code = 400
      err_msg = f"Missing value required for safe name: {input_keys[idx]}"
      logging.error(err_msg)
      response_body = err_msg

  if status_code == 200:
    # encode each input value and append to safe name
    for idx in range(0,len(input_vals)):
      if safe_name != "":
        safe_name += "-"
      enc_val = dispatch[idx](input_vals[idx])
      if enc_val is not None:
        safe_name += enc_val
      else:
        status_code = 400
        err_msg = f"Error encoding value for key {input_keys[idx]}: {input_vals[idx]}"
        logging.error(err_msg)
        response_body = err_msg

  logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

  return_dict = {}
  return_dict["status_code"] = status_code
  return_dict["response_body"] = response_body
  return_dict["safe_name"] = safe_name
  return return_dict
