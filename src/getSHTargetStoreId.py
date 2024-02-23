#############################################################################
#############################################################################
# getSHTargetStoreId.py

import json
import requests
import logging

# Exactly one target store for account/region must already exist in Secrets Hub.
# Uses account and region ID from provisioning request to find existing target store.
# Returns status_code == 200 for success, response_body with message and tstore_id

def getSHTargetStoreId(prov_req):
    logging.debug("================ getSHTargetStoreId() ================")

    # first ensure we have required request values
    required_keys = [
        "cybr_subdomain",
        "session_token",
        "cloudAccount",
        "cloudRegion"
    ]
    for rkey in required_keys:
        input_val = prov_req.get(rkey, None)
        if input_val is None:
            response_body = f"Request is missing key required for Secrets Hub target store retrieval: {rkey}"
            logging.error(response_body)
            return_dict = {}
            return_dict["status_code"] = 400
            return_dict["response_body"] = response_body

    cybr_subdomain = prov_req["cybr_subdomain"]
    session_token = prov_req["session_token"]
    account_id = str(prov_req["cloudAccount"])     # str() needed in case acct# is not quoted
    region_id = prov_req["cloudRegion"]

    tstore_id = ""
    status_code = 200
    response_body = "Target store retrieved successfully"

    url = f"https://{cybr_subdomain}.secretshub.cyberark.cloud/api/secret-stores"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.request("GET", url, headers=headers)
    status_code = response.status_code
    if status_code == 200:
        stores_dict = json.loads(response.text)

        # NEEDS REVISITING TO SUPPORT AZURE & GCP
        # filter out Source & non-AWS stores because they don't have entries for AWS account/region
        isAwsTarget = lambda x: (
            (x["type"] == "AWS_ASM") & ("SECRETS_TARGET" in x["behaviors"])
        )
        allAwsTargets = [t for t in stores_dict["secretStores"] if isAwsTarget(t)]
        logging.debug(f"allAwsTargets: {allAwsTargets}")

        isTheTarget = lambda x: (
            (x["data"]["accountId"] == account_id)
            & (x["data"]["regionId"] == region_id)
        )
        foundTarget = [a for a in allAwsTargets if isTheTarget(a)]
        if len(foundTarget) == 0:
            status_code = 404
            response_body = f"Target store not found for account {account_id} and region {region_id}."
        elif len(foundTarget) > 1:  # should not happen, but just in case
            status_code = 300
            response_body = f"More than one target store found for account {account_id} and region {region_id}."
        else:
            tstore_id = foundTarget.pop()["id"]
    else:
        response_body = response.text

    logging.debug(f"\ttstore_id: {tstore_id}")
    logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return_dict["store_id"] = tstore_id
    return return_dict
