
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

    # Validate all creds have a value, if not exit
    none_keys = [key for key, value in admin_creds.items() if value is None]
    if none_keys:
        print("Missing one of cybr_subdomain, cybr_username, cybr_password in admin_creds dictionary.")
        sys.exit(-1)
  
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
