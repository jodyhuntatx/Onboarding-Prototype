#############################################################################
#############################################################################
# getPlatform.py

import json
import logging

# ====================================================
# Constant - also referenced in createAccount.py
PLATFORM_FILE = "./platforms.json"  # file with platform mapping k/v pairs

# ====================================================
# Finds first platform where platform's searchpair values all match the provisioning request's
# Validates that all keys in provisionng request map to platform properties
# Returns platform id in response


def getPlatform(prov_req):
    logging.debug("================ getPlatformId() ================")

    # ensure provisioning request has account_values, if not exit w/ error
    if prov_req.get("account_values", None) is None:
        err_msg = "Provisioning request does not contain account values. Unable to determine platform."
        logging.error(err_msg)
        return_dict = {}
        return_dict["status_code"] = 400
        return_dict["response_body"] = err_msg
        return_dict["platform_id"] = "NoneFound"
        print(return_dict)

    # load platform dictionary from json file created with compileplats.py
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

    # Find platform where platform search keys & values == request keys & values
    plat_id = None
    for pid in platforms.keys():  # top-level platforms keys are platform IDs
        search_pairs = platforms[pid]["searchpairs"]
        logging.debug(f"pid: {pid}, searchpairs: {search_pairs}")
        # all k/v pairs in searchpairs must be found in the provisioning request for a match
        pair_counter = len(search_pairs)
        for pkey, pval in search_pairs.items():
            logging.debug(f"     pkey: {pkey}, pval: {pval}")
            rval = prov_req.get(pkey, None)  # get value of key in request, if any
            if rval is not None:
                logging.debug(
                    f"     platform: ({pkey},{pval}), request: ({pkey},{rval})"
                )
                if rval.upper() == pval.upper():
                    pair_counter -= 1  # k/v matches, decrement searchpair counter
                    if pair_counter == 0:  # if all k/v pairs have matched...
                        plat_id = pid
                        logging.info(f"Matching platform ID: {plat_id}")
                        break
                else:
                    break  # k/v does not match, on to next platform
        if plat_id is not None:  # if platform found, stop searching
            break

    if plat_id is None:
        err_msg = "No platform found with searchpairs that match request values."
        logging.info(err_msg)
        status_code = 404
        response_body = err_msg
        plat_id = "NotFound"
    else:
        plat_found = platforms[plat_id]
        # determine provisioning request keys map to platform properties
        valid_request = False

        # get list of uppercase request onboarding keys to compare with platform properties
        prov_list = prov_req["account_values"].keys()
        prov_keys = [k.upper() for k in prov_list]
        # first ensure all request properties are in platform keys
        logging.debug(f"prov_keys: type: {type(prov_keys)} vals: {prov_keys}")
        missing_keys = [k for k in prov_keys if k not in plat_found["allkeys"]]
        valid_request = len(missing_keys) == 0
        if valid_request:
            # then ensure all platform required keys are in request
            missing_keys = [k for k in plat_found["required"] if k not in prov_keys]
            valid_request = len(missing_keys) == 0
            if valid_request:
                status_code = 200
                response_body = f"Platform {plat_id} is a match for request."
                logging.info(response_body)
            else:
                status_code = 400
                req_keys = plat_found["required"]
                prov_keys = sorted(prov_keys)
                logging.error(
                    f"{plat_id} required propertie(s) '{missing_keys}' not found in request keys '{prov_keys}''."
                )
                response_body = f"One or more required platform properties not found in request keys."
                plat_id = "Missing-Required-Keys"
        else:
            status_code = 400
            prov_keys = sorted(prov_keys)
            all_keys = sorted(plat_found["allkeys"])
            logging.error(
                f"Request keys '{missing_keys}' not found in {plat_id} properties: '{all_keys}'."
            )
            response_body = f"One or more keys in the onboarding request were not found in the {plat_id} platform properties."
            plat_id = "Request-Platform-KeyMismatch"

    logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return_dict["platform_id"] = plat_id
    return return_dict
