#############################################################################
#############################################################################
# getSHSourceStoreId.py

import json
import requests
import logging

# Exactly one source store must already exist.
# Uses values in onboarding_dict to retrieve source store ID from Secrets Hub
# Returns ID, status_code == 200 for success, response_body with message

# -------------------------------------------
def getSHSourceStoreId(prov_req):
    logging.debug("================ getSHSourceStoreId() ================")

    # first ensure we have required request values
    required_keys = ["cybr_subdomain", "session_token"]
    for rkey in required_keys:
        input_val = prov_req.get(rkey, None)
        if input_val is None:
            response_body = f"Request is missing key required for Secrets Hub source store ID retrieval: {rkey}"
            logging.error(response_body)
            return_dict = {}
            return_dict["status_code"] = 400
            return_dict["response_body"] = response_body

    cybr_subdomain = prov_req["cybr_subdomain"]
    session_token = prov_req["session_token"]

    sstore_id = ""
    status_code = 200
    response_body = "Source store retrieved successfully"

    url = f"https://{cybr_subdomain}.secretshub.cyberark.cloud/api/secret-stores"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.request("GET", url, headers=headers)
    status_code = response.status_code
    if status_code == 200:
        stores_dict = json.loads(response.text)
        isSource = lambda store: "SECRETS_SOURCE" in store["behaviors"]
        foundSource = [store for store in stores_dict["secretStores"] if isSource(store)]
        if len(foundSource) == 0:
            status_code = 403
            response_body = "No secret source found."
        elif len(foundSource) > 1:
            status_code = 300
            response_body = "More than one secret source found."
        else:
            sstore_id = foundSource.pop()["id"]
    else:
        response_body = response.text

    logging.debug(f"\tsstore_id: {sstore_id}")
    logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return_dict["store_id"] = sstore_id
    return return_dict