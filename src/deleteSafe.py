
#############################################################################
#############################################################################
# deleteSafe.py

import json
import sys
import requests
import logging

def deleteSafe(prov_req):
    logging.debug("================ deleteSafe() ================")

    # first ensure we have required request values
    required_keys = ["cybr_subdomain", "session_token", "safe_name"]
    for rkey in required_keys:
        input_val = prov_req.get(rkey, None)
        if input_val is None:
            err_msg = f"Request is missing key required for safe deletion: {rkey}"
            logging.error(err_msg)
            return_dict = {}
            return_dict["status_code"] = 400
            return_dict["response_body"] = err_msg

    cybr_subdomain = prov_req["cybr_subdomain"]
    session_token = prov_req["session_token"]
    safe_name = prov_req["safe_name"]

    status_code = 204
    response_body = f"Safe {safe_name} deleted successfully."

    url = f"https://{cybr_subdomain}.privilegecloud.cyberark.cloud/passwordvault/api/safes/{safe_name}"
    headers = {
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.request("DELETE", url, headers=headers)
    status_code = response.status_code
    if status_code != 204:
        if status_code == 404:
            response_body = f"Safe {safe_name} not found."
        else:
            status_code = 500
            response_body = f"Error deleting safe {safe_name}"
            logging.debug(response_body)
            logging.debug(response.text)

    logging.debug("================ deleteSafe() ================")
    logging.debug(f"status_code: {status_code}\n\tresponse: {response_body}")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return return_dict