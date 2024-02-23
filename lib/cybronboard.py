
#############################################################################
#############################################################################
# addSafeMembers.py

import json
import requests
import logging

def addSafeMembers(prov_req):
    #====================================================
    sync_permissions = {
        "accessWithoutConfirmation": True,
        "listAccounts": True,
        "retrieveAccounts": True,
        "viewSafeMembers": True,
    }
    full_permission_delta = {
        "useAccounts": True,
    #    "retrieveAccounts": True,
    #    "listAccounts": True,
        "addAccounts": True,
        "updateAccountContent": True,
        "updateAccountProperties": True,
        "initiateCPMAccountManagementOperations": True,
        "specifyNextAccountContent": True,
        "renameAccounts": True,
        "deleteAccounts": True,
        "unlockAccounts": True,
        "manageSafe": False,
        "manageSafeMembers": True,
        "backupSafe": False,
        "viewAuditLog": True,
    #    "viewSafeMembers": True,
    #    "accessWithoutConfirmation": True,
        "createFolders": False,
        "deleteFolders": False,
        "moveAccountsAndFolders": False,
        "requestsAuthorizationLevel1": False
    }
    full_permissions = full_permission_delta | sync_permissions

    admin_permission_delta = {
    #    "useAccounts": True,
    #    "retrieveAccounts": True,
    #    "listAccounts": True,
    #    "addAccounts": True,
    #    "updateAccountContent": True,
    #    "updateAccountProperties": True,
    #    "initiateCPMAccountManagementOperations": True,
    #    "specifyNextAccountContent": True,
    #    "renameAccounts": True,
    #    "deleteAccounts": True,
    #    "unlockAccounts": True,
        "manageSafe": True,
    #    "manageSafeMembers": True,
        "backupSafe": True,
    #    "viewAuditLog": True,
    #    "viewSafeMembers": True,
    #    "accessWithoutConfirmation": True,
        "createFolders": True,
        "deleteFolders": True,
        "moveAccountsAndFolders": True,
        "requestsAuthorizationLevel1": True
    }
    admin_permissions = admin_permission_delta | full_permissions

    # Adds members of memberlist to safe w/ permissions
    # NOTE: safe_name, cybr_subdomain & session_token are global vars to this function
    def addMembers(memberList, permissions):
        status_code = 201
        response_body = f"All members added to safe {safe_name} successfully."
        for mbr in memberList:
            mbr = mbr.replace("%2f"," ").replace("%2F"," ")
            member_req = {
                "safeName": safe_name,
                "memberName": mbr,
                "memberType": "User",
                "searchIn": "Vault",
                "membershipExpirationDate": None
            }
            member_req["permissions"] = permissions
            url = f"https://{cybr_subdomain}.privilegecloud.cyberark.cloud/passwordvault/api/safes/{safe_name}/members"
            payload = json.dumps(member_req)
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {session_token}",
            }
            response = requests.request("POST", url, headers=headers, data=payload)
            status_code = response.status_code
            if status_code == 201:
                logging.info(f"{mbr} added to safe {safe_name}")
            elif status_code == 409:
                logging.info(f"User named {mbr} is already a member of safe {safe_name}.")              
            else:
                response_body = f"Error adding user named {mbr} to safe {safe_name}."
                logging.error(response_body)
                logging.error(f"\t{response.text}")

            if status_code not in [201,409]:
                break

        return status_code, response_body

    # MAIN ====================================================
    logging.debug("================ addSafeMembers() ================")

    # first ensure we have required request values
    required_keys = ["cybr_subdomain","session_token","safe_name"]
    for rkey in required_keys:
        input_val = prov_req.get(rkey, None)
        if input_val is None:
            err_msg = f"Request is missing key required for adding safe members: {rkey}"
            logging.error(err_msg)
            return_dict = {}
            return_dict["status_code"] = 400
            return_dict["response_body"] = err_msg

    cybr_subdomain = prov_req["cybr_subdomain"]
    session_token = prov_req["session_token"]
    safe_name = prov_req["safe_name"]

    # add safe admins first
    safe_admins = prov_req.get("safeAdmins", None)
    if safe_admins is not None:
        status_code, response_body = addMembers(safe_admins,admin_permissions)
    else: 
        logging.info(f"No admins to add to safe {safe_name}.")

    # if no errors, add full users (account managers)
    if status_code in [201,409]:
        safe_full_users = prov_req.get("safeFullUsers", None)
        if safe_full_users is not None:
            status_code, response_body = addMembers(safe_full_users,full_permissions)
        else:
            logging.info(f"No sync members to add to safe {safe_name}.")

    # if no errors, add sync users (SecretsHub, 'Conjur Sync', etc.)
    if status_code in [201,409]:
        sync_members = prov_req.get("syncMembers", None)
        if sync_members is not None:
            status_code, response_body = addMembers(sync_members,sync_permissions)
        else:
            logging.info(f"No sync members to add to safe {safe_name}.")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return return_dict

#############################################################################
#############################################################################
# authnCyberark.py

import os
import sys
import requests
import urllib.parse
import logging

# Authenticates with creds in dictionary argument.
# Returns session_token in response dictionary.

def authnCyberark(admin_creds):
    logging.debug("================ authnCyberark() ================")

    # -------------------------------------------
    def urlify(s):
        # URL encodes a given string
        return urllib.parse.quote(s)
    # -------------------------------------------

    # first ensure we have required request values
    required_keys = ["cybr_subdomain","cybr_username","cybr_password"]
    for rkey in required_keys:
        input_val = admin_creds.get(rkey, None)
        if input_val is None:
            err_msg = f"Admin creds is missing key required for authentication: {rkey}"
            logging.error(err_msg)
            return_dict = {}
            return_dict["status_code"] = 400
            return_dict["response_body"] = err_msg
  
    cybr_subdomain = admin_creds["cybr_subdomain"]
    cybr_username = admin_creds["cybr_username"]
    cybr_password = admin_creds["cybr_password"]

    # uses Pcloud creds to authenticate to CyberArk Identity
    # returns dictionary w/ session_token (CyberArk Identity JWT) to use in further CyberArk API calls

    session_token = ""
    status_code = 200
    response_body = "Successfully authenticated to CyberArk Privilege Cloud."

    # Authenticate to CyberArk Identity
    url = f"https://{cybr_subdomain}.cyberark.cloud/api/idadmin/oauth2/platformtoken"
    payload = f"grant_type=client_credentials&client_id={urlify(cybr_username)}&client_secret={urlify(cybr_password)}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.request("POST", url, headers=headers, data=payload)
    status_code = response.status_code
    if status_code == 200:
        # Parse the JSON response into a dictionary
        data = response.json()
        # Extract session token from the response dict
        session_token = data.get("access_token", None)
        if session_token is None:
            session_token = ""
            status_code = 401
            response_body = f"There was a problem authenticating to: {url}"
            logging.debug(response.text)
    else:
        status_code = 500
        response_body = f"There was a problem authenticating to: {url}"
        logging.debug(response_body)
        logging.debug(response.text)

    logging.debug(f"\turl: {url}\n\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return_dict["session_token"] = session_token
    return return_dict

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

#############################################################################
#############################################################################
# deleteAccount.py

import json
import requests
import logging

def deleteAccount(prov_req):
    logging.debug("================ deleteAccount() ================")
    response_body = "deleteAccount is not implemented yet."
    logging.debug(response_body)
    return_dict = {}
    return_dict["status_code"] = 400
    return_dict["response_body"] = response_body
    return return_dict

    # first ensure we have required request values
    required_keys = ["cybr_subdomain", "session_token", "safe_name"]
    for rkey in required_keys:
        input_val = prov_req.get(rkey, None)
        if input_val is None:
            err_msg = f"Request is missing key required for account deletion: {rkey}"
            logging.error(err_msg)
            return_dict = {}
            return_dict["status_code"] = 400
            return_dict["response_body"] = err_msg

    # Extract HTTPS values
    cybr_subdomain = prov_req["cybr_subdomain"]
    session_token = prov_req["session_token"]

    url = (
        f"https://{cybr_subdomain}.privilegecloud.cyberark.cloud/passwordvault/api/accounts"
    )
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session_token}",
    }
    search_url = url + f"?search={secret_id}"
    response = requests.request("get", search_url, headers=headers)
    status_code = response.status_code
    response_body = response.text
    if status_code == 200:
        account_dict = json.loads(response.text)
        num_found = account_dict["count"]
        match num_found:
            case 1:
                account_id = account_dict["value"][0]["id"]
                account_name = account_dict["value"][0]["name"]
                safe_name = account_dict["value"][0]["safeName"]
                delete_url = url + f"/{account_id}"
                response = requests.request("delete", delete_url, headers=headers)
                status_code = response.status_code
                if status_code == 204:
                    response_body = (
                        f"Account {account_name} in safe {safe_name} deleted successfully."
                    )
                else:
                    response_body = response.text
            case 0:
                status_code = 404
                response_body = f"No account found for secret_id: {secret_id}"
            case _:
                status_code = 409  # 409 == 'conflict'
                response_body = f"More than one account found for secret_id: {secret_id}"
    else:
        response_body = (
            f"Error searching for account corresponding to secret_id: {secret_id}"
        )

    logging.debug("================ deleteAccount() ================")
    logging.debug(f"\tsecret_id: {secret_id}")
    logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return return_dict

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
    return return_dict#############################################################################
#############################################################################
# deleteAccount.py

import sys
import logging

def errCheck(resp_dict, expected=[200]):
    if resp_dict["status_code"] not in expected:
        err_msg = f"{sys.argv[0]}: {resp_dict['response_body']}"
        print(err_msg)
        logging.error(err_msg)
        sys.exit(-1)
    return False
#############################################################################
#############################################################################
# getAuthnCreds.py

import os
import sys
import logging

# Pulls Pcloud admin cred values from environment variables.
# Returns creds in dictionary.

# This function encapsulates admin cred are retrieval,
#   to keep that separate from and to simplify authentication.

def getAuthnCreds():
    logging.debug("================ getAuthnCreds() ================")
    status_code = 200
    response_body = "Authentication credentials retrieved."
    admin_creds = {
        "cybr_subdomain": os.environ.get("CYBR_SUBDOMAIN",None),
        "cybr_username": os.environ.get("CYBR_USERNAME",None),
        "cybr_password": os.environ.get("CYBR_PASSWORD",None),
    }
    # Validate all creds have a value, if not exit with error code
    none_keys = [key for key, value in admin_creds.items() if value is None]
    if none_keys:
        status_code = 400
        response_body = "Missing one of CYBR_SUBDOMAIN, CYBR_USERNAME, CYBR_PASSWORD in environment variables."

    logging.info(response_body)

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return_dict["admin_creds"] = admin_creds
    return return_dict
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
    return return_dict#############################################################################
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
                "description": "Auto-created by onboarding automation",
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
    # first ensure we have required request values
    required_keys = [
        "cybr_subdomain",
        "session_token",
        "source_store_id",
        "target_store_id",
        "filter_id",
    ]
    for rkey in required_keys:
        input_val = prov_req.get(rkey, None)
        if input_val is None:
            response_body = f"Request is missing key required for Secrets Hub sync policy retrieval/creation: {rkey}"
            logging.error(response_body)
            return_dict = {}
            return_dict["status_code"] = 400
            return_dict["response_body"] = response_body

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
            ((x["source"]["id"] == sstore_id)
            & (x["target"]["id"] == tstore_id)
            & (x["filter"]["id"] == filter_id))
        )
        foundPolicy = [a for a in policies_dict["policies"] if isPolicy(a)]
        if len(foundPolicy) == 0:  # policy not found - create it
            policy_id, status_code, response_body = createSHSyncPolicy(
                cybr_subdomain, session_token, sstore_id, tstore_id, filter_id
            )
        elif len(foundPolicy) > 1:
            status_code = 300
            response_body = f"More than one sync policy found for source ID {sstore_id}, filter ID {filter_id}, target ID {tstore_id}."
            policy_id = foundPolicy.pop()["id"]
        else:
            policy = foundPolicy.pop()
            policy_id = policy["id"]
            if policy["state"]["current"] != "ENABLED":
                status_code = 409
                response_body = f"Policy ID {policy_id} is not currently enabled."
    else:
        response_body = response.text

    logging.debug(f"\tpolicy_id: {policy_id}")
    logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return_dict = {}
    return_dict["status_code"] = status_code
    return_dict["response_body"] = response_body
    return_dict["policy_id"] = policy_id
    return return_dict
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

#############################################################################
#############################################################################
# getSafeName.py

import json
import logging

# Generates safe name base on provisioning record values and rules
#  defined in ./json/safenamerules.json (path is relative to function
#  calling this function).

def getSafeName(prov_req):

  with open("./json/safenamerules.json") as sr:
      saferules = json.load(sr)

  logging.debug("================ getSafeName() ================")
  status_code = 200
  response_body = "Safe name generated."
  safe_name = ""

  # first ensure we have request values required for rules
  # get names of request keys in rules from which to compose safe name
  required_keys = [ r["keyname"] for r in saferules ]
  for idx in range(len(required_keys)):
    input_val = prov_req.get(required_keys[idx],None)
    if input_val is None:
      status_code = 400
      err_msg = f"Missing key required for safe naming: {required_keys[idx]}"
      logging.error(err_msg)
      response_body = err_msg

  # all values converted to uppercase strings for comparisons
  if status_code == 200:
    for rule in saferules:
        keyval = prov_req[rule["keyname"]]
        outval = None
        match rule["maptype"]:
            case "valuemap":
                for vmap in rule["valuemap"]:
                    upvals = [v.upper() for v in vmap["inputs"]]
                    if str(keyval).upper() in upvals:
                        outval = vmap["output"].upper()
                        break
            case "literal":
                outval = str(keyval).upper()
            case "substring":
                beg = rule["substring"]["start"]
                if beg > len(str(keyval)):
                  beg = 0             # dubious error correction
                end = rule["substring"]["end"]
                if end > len(str(keyval)):
                  end = len(str(keyval))
                outval = str(keyval)[beg:end].upper()
            case _:
                logging.error(f"Invalid maptype: {rule['maptype']}")

        if outval is not None:
            if safe_name != "":
                safe_name += "-"
            safe_name += outval
        else:
            status_code = 400
            err_msg = f"No safename mapping rule found for {keyval}"
            logging.error(err_msg)
            response_body = err_msg
            break

  logging.debug(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

  return_dict = {}
  return_dict["status_code"] = status_code
  return_dict["response_body"] = response_body
  return_dict["safe_name"] = safe_name
  return return_dict
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
