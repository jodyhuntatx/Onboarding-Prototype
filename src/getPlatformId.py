#############################################################################
#############################################################################
# getPlatformId.py

import json
import logging

# ====================================================
# Constants
PLATFORM_FILE = "./json/platforms.json"  # file with platform mapping k/v pairs
# PLATFORM_FILE is also referenced in validateRequestWithPlatform.py and createAccount.py

# ====================================================
# Finds first platform where platform's searchpair values all match the provisioning request's
# If found, returns status_code == 200 and platform id in response


def getPlatformId(prov_req):
    logging.debug("================ getPlatformId() ================")

    # first ensure we have required request values
    required_keys = ["cybr_subdomain", "session_token", "safe_name"]
    for rkey in required_keys:
        input_val = prov_req.get(rkey, None)
        if input_val is None:
            response_body = f"Request is missing key required for platform identification: {rkey}"
            logging.error(response_body)
            return_dict = {}
            return_dict["status_code"] = 400
            return_dict["response_body"] = response_body

    # load platform dictionary from json file created with compileplats.py
    try:
        with open(PLATFORM_FILE) as f_in:
            platforms = json.load(f_in)
    except IOError:
        response_body = f"Could not read file: {PLATFORM_FILE}"
        logging.error(response_body)
        return_dict = {}
        return_dict["status_code"] = 500
        return_dict["response_body"] = response_body
        return return_dict

    status_code = 200
    response_body = "Platform found."

    # Find platform where platform search keys & values == request keys & values
    plat_id = None
    for pid in platforms.keys():  # top-level platforms keys are platform IDs
        search_pairs = platforms[pid]["searchpairs"]
        logging.debug(f"pid: {pid}, searchpairs: {search_pairs}")
        # all k/v pairs in searchpairs must be found in the provisioning request for a match
        pair_counter = len(search_pairs)
        for pkey, pval in search_pairs.items():
            logging.debug(f"\tpkey: {pkey}, pval: {pval}")
            rval = prov_req.get(pkey, None)  # get value of key in request, if any
            if rval is not None:
                logging.debug(f"\tplatform: ({pkey},{pval}), request: ({pkey},{rval})")
                if rval.upper() == pval.upper():
                    pair_counter -= 1  # k/v matches, decrement searchpair counter
                    if pair_counter == 0:  # if all k/v pairs have matched...
                        plat_id = pid
                        response_body = f"Matching platform ID: {plat_id}"
                        break
                else:
                    break  # k/v does not match, on to next platform
        if plat_id is not None:  # if platform found, stop searching
            break

    if plat_id is None:
        response_body = "No platform found with searchpairs that match request values."
        logging.error(response_body)
        status_code = 404
        plat_id = "NotFound"

    logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return_dict["platform_id"] = plat_id
    return return_dict
