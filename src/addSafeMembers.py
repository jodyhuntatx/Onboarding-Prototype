
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
