#############################################################################
#############################################################################
# getSHFilterForSafe.py

import json
import sys
import requests
import logging

# Does not assume filter exists in Secrets Hub.
# Uses source_store_id and safename from provisioning request to find policy filter for safe.
# If filter doesn't exist, creates it.
# Returns status_code == 200 or 201 for success, response_body with message, filter_id.

# -------------------------------------------
def getSHFilterForSafe(prov_req):
    logging.debug("================ getSHFilterForSafe() ================")

    # -------------------------------------------
    # NOTE: cybr_subdomain, source_store_id, safe_name are global vars to this function
    def createSHFilterForSafe():
        logging.debug("================ createSHFilterForSafe() ================")
        filter_id = ""
        url = f"https://{cybr_subdomain}.secretshub.cyberark.cloud/api/secret-stores/{source_store_id}/filters"
        payload = json.dumps({"data": {"safeName": safe_name}, "type": "PAM_SAFE"})
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {session_token}",
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        status_code = response.status_code
        if status_code == 201:
            filter_dict = json.loads(response.text)
            filter_id = filter_dict["id"]
            response_body = (
                f"Filter for store ID {source_store_id} and safe {safe_name} created."
            )
        else:
            status_code = response.status_code
            response_body = response.text

        logging.debug(f"\tfilter_id: {filter_id}")
        logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

        return filter_id, status_code, response_body

    # -------------------------------------------
    # first ensure we have required request values
    required_keys = ["cybr_subdomain", "session_token", "safe_name", "source_store_id"]
    for rkey in required_keys:
        input_val = prov_req.get(rkey, None)
        if input_val is None:
            response_body = f"Request is missing key required for Secrets Hub filter retrieval/creation: {rkey}"
            logging.error(response_body)
            return_dict = {}
            return_dict["status_code"] = 400
            return_dict["response_body"] = response_body

    cybr_subdomain = prov_req["cybr_subdomain"]
    session_token = prov_req["session_token"]
    safe_name = prov_req["safe_name"]
    source_store_id = prov_req["source_store_id"]

    filter_id = ""
    status_code = 0
    response_body = f"Source store filter for store ID {source_store_id} and safe {safe_name} retrieved successfully."

    # get all filters
    url = f"https://{cybr_subdomain}.secretshub.cyberark.cloud/api/secret-stores/{source_store_id}/filters"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.request("GET", url, headers=headers)
    status_code = response.status_code
    if status_code == 200:
        # see if filter already exists for safe
        filters_dict = json.loads(response.text)
        isFilter = lambda x: (
            (x["type"] == "PAM_SAFE") & (x["data"]["safeName"] == safe_name)
        )
        foundFilter = [a for a in filters_dict["filters"] if isFilter(a)]
        if len(foundFilter) == 0:  # filter does not exist - create it
            filter_id, status_code, response_body = createSHFilterForSafe()
        elif len(foundFilter) == 1:  # filter already exists - use it
            filter_id = foundFilter.pop()["id"]
        else:  # more than one filter exists - ambiguous - should not happen
            status_code = 300
            response_body = f"More than one filter already exists for store ID {source_store_id} and safe {safe_name}."
    else:
        response_body = response.text

    logging.debug(f"\tfilter_id: {filter_id}")
    logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return_dict["filter_id"] = filter_id
    return return_dict
