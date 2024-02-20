#############################################################################
#############################################################################
# getSHSyncPolicy.py

import json
import sys
import requests
import logging

# Does not assume sync policy exists in Secrets Hub.
# Uses IDs from dict to find existing policy.
# If policy not fount, creates it.
# Returns policy_id, status_code == 200 or 201 for success, response_body with message


# -------------------------------------------
def getSHSyncPolicy(prov_req):
    logging.debug("================ getSHSyncPolicy() ================")

    # -------------------------------------------
    def createSHSyncPolicy(
        cybr_subdomain, session_token, sstore_id, tstore_id, filter_id
    ):
        # should probably get source, target, filter names for policy name/description
        url = f"https://{cybr_subdomain}.secretshub.cyberark.cloud/api/policies"
        payload = json.dumps(
            {
                "name": "ASM policy",
                "description": "Auto-created by onboarding lambda",
                "source": {"id": sstore_id},
                "target": {"id": tstore_id},
                "filter": {"id": filter_id},
            }
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {session_token}",
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        status_code = response.status_code
        if status_code == 201:
            policy_dict = json.loads(response.text)
            policy_id = policy_dict["id"]
            response_body = f"Policy with source ID {sstore_id}, target ID {tstore_id}, filter ID {filter_id} created."
        else:
            status_code = response.status_code
            response_body = response.text

        logging.debug(f"\tpolicy_id: {policy_id}")
        logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

        return policy_id, status_code, response_body

    # MAIN ====================================================

    cybr_subdomain = prov_req["cybr_subdomain"]
    session_token = prov_req["session_token"]
    sstore_id = prov_req["source_store_id"]
    tstore_id = prov_req["target_store_id"]
    filter_id = prov_req["filter_id"]

    policy_id = ""
    status_code = 200
    response_body = "Sync policy retrieved successfully"

    url = f"https://{cybr_subdomain}.secretshub.cyberark.cloud/api/policies"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.request("GET", url, headers=headers)
    status_code = response.status_code
    if status_code == 200:
        policies_dict = json.loads(response.text)
        isPolicy = lambda x: (
            (x["state"]["current"] == "ENABLED")
            & (x["source"]["id"] == sstore_id)
            & (x["target"]["id"] == tstore_id)
            & (x["filter"]["id"] == filter_id)
        )
        foundPolicy = [a for a in policies_dict["policies"] if isPolicy(a)]
        if len(foundPolicy) == 0:  # policy not found - create it
            policy_id, status_code, response_body = createSHSyncPolicy(
                cybr_subdomain, session_token, sstore_id, tstore_id, filter_id
            )
        elif len(foundPolicy) > 1:
            status_code = 300
            response_body = "More than one sync policy found for source ID {sstore_id}, filter ID {filter_id}, target ID {tstore_id}."
        else:
            policy_id = foundPolicy.pop()["id"]
    else:
        response_body = response.text

    logging.debug(f"\tpolicy_id: {policy_id}")
    logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return_dict["policy_id"] = policy_id
    return return_dict
