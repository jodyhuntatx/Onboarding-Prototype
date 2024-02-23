
#############################################################################
#############################################################################
# createAccount.py

import json
import requests
import logging

def createAccount(prov_req):
    logging.debug("================ createAccount() ================")

    # ensure provisioning request has accountValues, if not exit w/ error
    if prov_req.get("accountValues",None) is None:
        err_msg = "Provisioning request does not contain account values. Unable to create account."
        logging.error(err_msg)
        return_dict = {}
        return_dict["status_code"] = 400
        return_dict["response_body"] = err_msg
        return return_dict

    # load platform dictionary from json file created with compileplats.py
    # PLATFORM_FILE is a constant defined in getPlatform.py
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

    # Extract provisioning request values
    cybr_subdomain = prov_req["cybr_subdomain"]
    session_token = prov_req["session_token"]
    platform_id = prov_req["platform_id"]
    safe_name = prov_req["safe_name"]

    status_code = 201
    response_body = f"Account created successfully."

    # Construct account request from values in provisioning request
    acct_props = prov_req["accountValues"]
    logging.debug("accountValues:",acct_props)

    # Construct account name per vault naming algorithm
    acct_name = platforms[platform_id]["systemtype"]
    acct_name += "-" + platform_id
    acct_name += "-" + acct_props["address"]
    acct_name += "-" + acct_props["username"]

    account_req = {
        "safeName": safe_name,
        "platformID": platform_id,
        "name": acct_name
    }
    # add required properties to account_request
    reqs_plat_props = platforms[platform_id]["required"]
    for key, val in acct_props.items():
        if key.upper() in reqs_plat_props:
            account_req[key] = acct_props[key]

    # secret and username are optional, but are not platformAccountProperties
    secret = acct_props.get("secret",None)
    if secret is not None:
        # hardcode password type for now - need to revisit for key type
        account_req["secretType"] = "password"  
        account_req["secret"] = secret
        acct_props.pop("secret")
    username = acct_props.get("username",None)
    if username is not None:
        account_req["username"] = username 
        acct_props.pop("username")

    account_req["secretManagement"] = {
        "automaticManagementEnabled": True
    }
    # add optional values to account properties
    account_req["platformAccountProperties"] = {}
    for key, val in acct_props.items():
        if key.upper() not in reqs_plat_props:
            account_req["platformAccountProperties"][key] = acct_props[key]

    logging.debug(f"account_req: {account_req}")

    url = f"https://{cybr_subdomain}.privilegecloud.cyberark.cloud/passwordvault/api/accounts"
    payload = json.dumps(account_req)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    status_code = response.status_code
    logging.debug(response.text)
    if status_code != 201:
        if response.status_code == 409:
            status_code = 409
            response_body = f"Account with the name {acct_name} already exists."
        else:
            response_body = "Invalid request format."
            logging.debug(response_body)
            logging.debug(response.text)

    logging.debug(f"\turl: {url}\n\tpayload: {payload}")
    logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return return_dict
