#############################################################################
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