#############################################################################
#############################################################################
# createSafe(prov_req)

import json
import requests
import logging


def createSafe(prov_req):
    logging.debug("================ createSafe() ================")

    # first ensure we have required request values
    required_keys = ["cybr_subdomain", "session_token", "safe_name"]
    for rkey in required_keys:
        input_val = prov_req.get(rkey, None)
        if input_val is None:
            err_msg = f"Request is missing key required for safe creation: {rkey}"
            logging.error(err_msg)
            return_dict = {}
            return_dict["status_code"] = 400
            return_dict["response_body"] = err_msg

    cybr_subdomain = prov_req["cybr_subdomain"]
    session_token = prov_req["session_token"]
    safe_name = prov_req["safe_name"]

    status_code = 201
    response_body = f"Safe {safe_name} created successfully."

    safe_req = {
        "safeName": safe_name,
        "description": "Created by CybrOnboarding engine.",
        "olacEnabled": "False",
        "managingCPM": "",
        "numberOfDaysRetention": 0,
    }
    url = f"https://{cybr_subdomain}.privilegecloud.cyberark.cloud/passwordvault/api/safes"
    payload = json.dumps(safe_req)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    status_code = response.status_code
    if status_code != 201:
        if status_code == 409:
            response_body = f"Safe {safe_name} already exists."
        else:
            status_code = 500
            response_body = f"Unknown error creating safe {safe_name}."
            logging.debug(response_body)
            logging.debug(response.text)

    logging.debug(f"status_code: {status_code}\n\tresponse: {response_body}")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return return_dict
