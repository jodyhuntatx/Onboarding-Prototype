#############################################################################
#############################################################################
# validateRequestWithPlatform.py

import json
import logging

# ====================================================
# Validates that all keys in provisionng request map to platform properties
# Returns status_code == 200 if valid, 400 if not


def validateRequestWithPlatform(prov_req):
    logging.debug("================ validateRequestWithPlatform() ================")

    # first ensure we have request values required for rules
    # get names of request keys in rules from which to compose safe name
    required_keys = ["platform_id","accountValues"]
    for rkey in required_keys:
        input_val = prov_req.get(rkey, None)
        if input_val is None:
            err_msg = f"Request is missing key required for platform validation: {rkey}"
            logging.error(err_msg)
            return_dict = {}
            return_dict["status_code"] = 400
            return_dict["response_body"] = err_msg

    # load platform dictionary from json file created with compileplats.py
    # PLATFORM_FILE is a global constant defined in getPlatform.py
    try:
        with open(PLATFORM_FILE) as f_in:
            platforms = json.load(f_in)
    except IOError:
        err_msg = f"Could not read file: {PLATFORM_FILE}"
        logging.error(err_msg)
        return_dict = {}
        return_dict["status_code"] = 500
        return_dict["response_body"] = err_msg
        return return_dict

    status_code = 200
    response_body = "Platform is valid"

    # determine if provisioning request keys map to platform properties
    plat_id = platforms[prov_req["platform_id"]]
    valid_request = False
    # get list of uppercase request properties to compare with platform properties
    prov_keys = [k.upper() for k in prov_req["accountValues"].keys()]
    # first check if request has properties that are not in platform keys
    missing_keys = [k for k in prov_keys if k not in plat_id["allkeys"]]
    valid_request = (len(missing_keys) == 0)
    if valid_request:
        # then check if any required platform properties are not in request
        missing_reqd_keys = [k for k in plat_id["required"] if k not in prov_keys]
        valid_request = (len(missing_reqd_keys) == 0)
        if valid_request:
            status_code = 200
            response_body = f"Platform {plat_id} is a match for request."
            logging.info(response_body)
        else:
            prov_keys = sorted(prov_keys)
            status_code = 400
            response_body = f"{plat_id} required propertie(s) '{missing_reqd_keys}' not found in request keys '{prov_keys}''."
            logging.error(response_body)
            plat_id = "Missing-Required-Keys"
    else:
        prov_keys = sorted(prov_keys)
        all_keys = sorted(plat_id["allkeys"])
        status_code = 400
        response_body = f"Request keys '{missing_keys}' not found in {plat_id} properties: '{all_keys}'."
        logging.error(response_body)
        plat_id = "Request-Platform-KeyMismatch"

    logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return return_dict
