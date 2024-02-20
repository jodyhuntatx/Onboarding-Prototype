
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
    admin_creds = {
        "cybr_subdomain": os.environ.get("CYBR_SUBDOMAIN",None),
        "cybr_username": os.environ.get("CYBR_USERNAME",None),
        "cybr_password": os.environ.get("CYBR_PASSWORD",None),
    }
    # Validate all creds have a value, if not exit with error code
    none_keys = [key for key, value in admin_creds.items() if value is None]
    if none_keys:
        print("Missing one of CYBR_SUBDOMAIN, CYBR_USERNAME, CYBR_PASSWORD in environment variables.")
        sys.exit(-1)

    logging.debug("Authentication credentials retrieved.")

    return admin_creds
