
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
