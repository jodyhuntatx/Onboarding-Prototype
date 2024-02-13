"""Module to retrieve metadata from a secret in AWS Secrets Manager
and use them to onboard the secret to CyberArk Privilege Cloud"""

import json
import os
import urllib.parse
import requests
import boto3
from botocore.exceptions import ClientError

# CONSTANTS
# Be sure to set to False for production to prevent secret leakage
DEBUG = True

# environment variable containing name of Pcloud admin secret in ASM
PCLOUD_ADMIN_SECRET_ENV_VAR = "PrivilegeCloudSecret"

# mapping of ASM engine types to CyberArk platform IDs
PLATFORM_MAP = {
    "mysql": "MySQL-ASM",
    "postgres": "PostgreSQL-ASM",
    "mariadb": "MariaDB-ASM",
    "oracle": "Oracle-ASM",
    "sqlserver": "MSSQL-ASM",
    "db2": "DB2SSH-ASM",
}


# -------------------------------------------
def urlify(s):
    # URL encodes a given string
    return urllib.parse.quote(s)


# -------------------------------------------
def prologOut(event, context):
    if DEBUG:
        print("Received event: " + json.dumps(event, indent=2))

    # Print the context to see its structure (useful for debugging)
    print("Lambda function ARN: " + context.invoked_function_arn)
    print("CloudWatch log stream name: " + context.log_stream_name)
    print("CloudWatch log group name: " + context.log_group_name)
    print("Lambda Request ID: " + context.aws_request_id)
    print("Lambda function memory limits in MB: " + context.memory_limit_in_mb)


# -------------------------------------------
def validateSecretMetadata(secrets_manager_client, secret_id):
    # Validate secret is tagged w/ 'Sourced by CyberArk' - if not, flag as not found
    # returns dictionary of secret metadata, status_code & response_body message

    secmeta_dict = {}
    status_code = 200
    response_body = f"Secret {secret_id} is sourced by CyberArk"

    # Retrieve tags of the secret
    try:
        response = secrets_manager_client.describe_secret(SecretId=secret_id)
    except ClientError as e:
        status_code = 500
        response_body = json.dumps(f"Error getting description for secret: {e}")
    else:
        tags = response.get("Tags", [])
        secmeta_dict = {tag["Key"].strip(): tag["Value"].strip() for tag in tags}

        # verify required tags are found
        if "Sourced by CyberArk" not in secmeta_dict:
            status_code = 404
            response_body = f"Secret {secret_id} not tagged with 'Sourced by CyberArk'. Check upper/lower case & for any trailing space chars."
        elif "CyberArk Safe" not in secmeta_dict:
            status_code = 404
            response_body = f"Secret {secret_id} not tagged with 'CyberArk Safe'. Check upper/lower case & for any trailing space chars."
        else:
            # parse secret ARN for account # & region ID
            secmeta_dict["AWS Account"] = response.get("ARN").split(":")[4]
            secmeta_dict["AWS Region"] = response.get("ARN").split(":")[3]

        # If "CyberArk Account" tag found, use its value, else use secretId for account name
        accountName = secmeta_dict.get("CyberArk Account", None)
        if accountName is None:
            # replace invalid '-' chars - may need to revisit
            accountName = secret_id.replace('/','-')
            secmeta_dict["CyberArk Account"] = accountName

    if DEBUG:
        print("================ validateSecretTags() ================")
        print(f"\tsecret_id: {secret_id}\n\tsecmeta_dict: {secmeta_dict}")
        print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return secmeta_dict, status_code, response_body


# -------------------------------------------
def getAsmSecretValue(secrets_manager_client, secret_id):
    # uses client & secret_id to retrieve value of secret
    # returns secret_value dictionary, status_code & message for response_body

    secret_value = {}
    status_code = 200
    response_body = "Secret retrieved successfully."

    try:
        response = secrets_manager_client.get_secret_value(SecretId=secret_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            status_code = 404
            response_body = json.dumps(
                f"The requested secret {secret_id} was not found."
            )
        elif e.response["Error"]["Code"] == "AccessDeniedException":
            status_code = 403
            response_body = json.dumps(
                f"Access to the requested secret {secret_id} was denied."
            )
        elif e.response["Error"]["Code"] == "InvalidRequestException":
            status_code = 500
            response_body = json.dumps(f"The request was invalid due to: {e}")
        elif e.response["Error"]["Code"] == "InvalidParameterException":
            status_code = 500
            response_body = json.dumps(f"The request had invalid params: {e}")
        elif e.response["Error"]["Code"] == "DecryptionFailure":
            status_code = 500
            response_body = json.dumps(
                f"The requested secret can't be decrypted using the provided KMS key: {e}"
            )
        elif e.response["Error"]["Code"] == "InternalServiceError":
            status_code = 500
            response_body = json.dumps(f"An error occurred on service side: {e}")
        else:
            status_code = 500
            response_body = json.dumps(f"Unknown error: {e}")
    else:
        secret_value = json.loads(response.get("SecretString", None))

    if DEBUG:
        print("================ getAsmSecretValue() ================")
        print(f"\tsecret_id: {secret_id}\n\tsecret_value: {secret_value}")
        print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return secret_value, status_code, response_body


# -------------------------------------------
def assembleOnboardingDict(admin_dict, secmeta_dict, secret_dict):
    #
    # returns onboarding dictionary, status_code & response_body message

    status_code = 200
    response_body = "Onboarding dictionary assembled successfully."
    print("secret_dict: ", secret_dict)
    onboarding_dict = {
        # values pulled from service account secret
        "subdomain": admin_dict.get("subdomain", None),
        "svc_username": admin_dict.get("username", None),
        "svc_password": admin_dict.get("password", None),
        # values pulled from secret metadata
        "awsAccount": secmeta_dict.get("AWS Account", None),
        "awsRegion": secmeta_dict.get("AWS Region", None),
        "safe": secmeta_dict.get("CyberArk Safe", None),
        "account": secmeta_dict.get("CyberArk Account", None),
        # values pulled from secret value to map to optional properties in CyberArk DB accounts
        "secretId": secret_dict.get("secretId", None),
        "username": secret_dict.get("username", None),
        "password": secret_dict.get("password", None),
        "host": secret_dict.get("host", None),
        "engine": secret_dict.get("engine", None),
        "port": secret_dict.get("port", None),
        # map RDS values to respective CyberArk properties
        "address": secret_dict.get("host", None),
        "platformId": PLATFORM_MAP.get(secret_dict.get("engine", None), None),
    }

    # RDS secrets may have dbname and/or dbInstanceIdentifier
    dbInstId = secret_dict.get("dbInstanceIdentifier", None)
    if dbInstId is not None:
        onboarding_dict["dbInstanceIdentifier"] = dbInstId
    dbName = secret_dict.get("dbname", None)
    if dbName is not None:
        onboarding_dict["dbname"] = dbName
        onboarding_dict["database"] = dbName

    # Allow for capitalization of port - bug in SecretsHub?
    # If no value for port, get secret value for 'host', if any
    if onboarding_dict["port"] is None:
        onboarding_dict["port"] = secret_dict.get("Port", None)

    # Validate no keys contain None as a value, if any, exit w/ 404
    none_keys = [key for key, value in onboarding_dict.items() if value is None]
    if none_keys:
        status_code = 404
        response_body = json.dumps(f"Required key value(s) not found: {none_keys}")

    if DEBUG:
        print("================ assembleOnboardingDict() ================")
        print(f"\nonboarding_dict: {onboarding_dict}")
        print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return onboarding_dict, status_code, response_body


# -------------------------------------------
def authnCyberArk(admin_dict):
    # uses Pcloud creds in admin_dict to authenticate to CyberArk Identity
    # returns session_token (CyberArk Identity JWT) to use in further CyberArk API calls

    session_token = None
    status_code = 200
    response_body = "Successfully authenticated to CyberArk Privilege Cloud."

    # Authenticate to CyberArk Identity
    url = f"https://{admin_dict['subdomain']}.cyberark.cloud/api/idadmin/oauth2/platformtoken"
    payload = f"grant_type=client_credentials&client_id={urlify(admin_dict['username'])}&client_secret={urlify(admin_dict['password'])}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.request("POST", url, headers=headers, data=payload)
    if response.status_code == 200:
        # Parse the JSON response into a dictionary
        data = response.json()
        # Extract session token from the response dict
        session_token = data.get("access_token", None)
        if session_token is None:
            status_code = 401
            response_body = json.dumps(
                f"There was a problem authenticating to: {admin_dict['subdomain']}.privilegecloud.cyberark.cloud"
            )
    else:
        status_code = 500
        response_body = json.dumps(
            f"There was a problem authenticating to: {admin_dict['subdomain']}.privilegecloud.cyberark.cloud"
        )

    if DEBUG:
        print("================ authnCyberark() ================")
        print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return session_token, status_code, response_body


# -------------------------------------------
def createSafe(onboarding_dict, session_token):
    # Uses info in dictionary to create a safe in Privilege Cloude
    # returns status_code == 201 on success with response_body message

    status_code = 201
    response_body = f"Safe {onboarding_dict['safe']} created successfully"

    url = f"https://{onboarding_dict['subdomain']}.privilegecloud.cyberark.cloud/passwordvault/api/safes"
    payload = json.dumps(
        {
            "safeName": onboarding_dict["safe"],
            "description": "Created by AWS Secrets Manager",
            "olacEnabled": False,
            "managingCPM": "PasswordManager",
            "numberOfDaysRetention": 0,
        }
    )
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.request(
        "POST", url, headers=headers, data=payload
    )  # timeout is governed by lambda config
    if response.status_code == 409:
        status_code = 409
        response_body = json.dumps(f"Safe {onboarding_dict['safe']} already exists")
    else:
        status_code = 500
        response_body = response.text

    if DEBUG:
        print("================ createSafe() ================")
        print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return status_code, response_body


# -------------------------------------------
def onboardAccount(onboarding_dict, session_token):
    # uses values in onboarding_dict to create account
    # returns status_code == 201 for success, response_body with message

    status_code = 201
    response_body = json.dumps(
        f"Account {onboarding_dict['account']} onboarded successfully"
    )

    url = f"https://{onboarding_dict['subdomain']}.privilegecloud.cyberark.cloud/passwordvault/api/accounts"
    # Set base payload of required parameters that are guaranteed to be in the onboarding_dict
    payload_dict = {
        "safeName": onboarding_dict["safe"],
        "platformID": onboarding_dict["platformId"],
        "name": onboarding_dict["account"],
        "address": onboarding_dict["address"],
        "userName": onboarding_dict["username"],
        "secretType": "password",
        "secret": onboarding_dict["password"],
        "secretManagement": {"automaticManagementEnabled": True},
        "platformAccountProperties": {
            "port": onboarding_dict["port"],
            "host": onboarding_dict["host"],
            "engine": onboarding_dict["engine"],
            "SecretNameInSecretStore": onboarding_dict["secretId"],
        },
    }

    # Add optional DB creation parameters
    if onboarding_dict.get("dbInstanceIdentifier", None) is not None:
        payload_dict["platformAccountProperties"][
            "dbInstanceIdentifier"
        ] = onboarding_dict["dbInstanceIdentifier"]
    """
    Currently setting database to the value of dbname.
    This may need revisiting as apparently dbname means different things for different DB engines.

    from: https://stackoverflow.com/questions/56763648/what-is-the-difference-between-dbinstanceidentifier-and-dbname-for-rds-create-db
    DBName does different things depending on the engine:
     - the name of a blank/empty schema that you want the service to automatically create inside your new instance (MySQL, Aurora/MySQL, and MariaDB, the default is not to create a schema; this option serves no real purpose unless for some reason you want one empty schema to be created automatically)
     - the name it will use instead of the default, to create a new database after launch (Postgres, default postgres is created otherwise)
     - the SID of the instance (Oracle, default ORCL)
     - a forbidden field (MSSQL).
    """
    if onboarding_dict.get("dbname", None) is not None:
        payload_dict["platformAccountProperties"]["dbname"] = onboarding_dict["dbname"]
        payload_dict["platformAccountProperties"]["database"] = onboarding_dict[
            "dbname"
        ]
    # convert dict to json
    payload = json.dumps(payload_dict)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    status_code = response.status_code
    if status_code != 201:
        if response.status_code == 409:
            status_code = 409
            response_body = json.dumps(
                f"Account {onboarding_dict['account']} already exists"
            )
        else:
            status_code = 500
            response_body = response.text

    if DEBUG:
        print("================ onboardAccount() ================")
        print(f"\turl: {url}\n\tpayload: {payload}")
        print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return status_code, response_body


# -------------------------------------------
def addSHUserToSafe(onboarding_dict, session_token):
    # Uses safe name value in onboarding_dict to add Secrets Hub user to safe
    # Returns status_code == 200 or 409 (already exists) for success, response_body with message

    safe_name = onboarding_dict["safe"]
    status_code = 200
    response_body = f"The SecretsHub user was successfully added to safe {safe_name}."

    url = f"https://{onboarding_dict['subdomain']}.privilegecloud.cyberark.cloud/passwordvault/api/safes/{safe_name}/members/"
    payload = json.dumps(
        {
            "memberName": "SecretsHub",
            "memberType": "User",
            "permissions": {
                "accessWithoutConfirmation": True,
                "listAccounts": True,
                "retrieveAccounts": True,
                "viewSafeMembers": True,
            },
        }
    )
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    response_body = response.text
    status_code = response.status_code
    if status_code != 201:
        if status_code == 409:
            response_body = (
                f"The SecretsHub user is already a member of safe {safe_name}."
            )

    if DEBUG:
        print("================ addSHUserToSafe() ================")
        print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return status_code, response_body


# -------------------------------------------
def getSHSourceStoreId(onboarding_dict, session_token):
    # Exactly one source store must already exist.
    # Uses values in onboarding_dict to retrieve source store ID from Secrets Hub
    # Returns ID, status_code == 200 for success, response_body with message

    sstore_id = ""
    status_code = 200
    response_body = "Source store retrieved successfully"

    url = f"https://{onboarding_dict['subdomain']}.secretshub.cyberark.cloud/api/secret-stores"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.request("GET", url, headers=headers)
    status_code = response.status_code
    if status_code == 200:
        stores_dict = json.loads(response.text)
        isSource = lambda x: "SECRETS_SOURCE" in x["behaviors"]
        foundSource = [a for a in stores_dict["secretStores"] if isSource(a)]
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

    if DEBUG:
        print("================ getSHSourceStoreId() ================")
        print(f"\tsstore_id: {sstore_id}")
        print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return sstore_id, status_code, response_body


# -------------------------------------------
def getSHFilterForSafe(onboarding_dict, session_token, store_id):
    # Does not assume filter exists in Secrets Hub.
    # Uses store_id and safename from dict to find policy filter for safe.
    # If filter doesn't exist, creates it.
    # Returns filter_id, status_code == 200 or 201 for success, response_body with message

    # -------------------------------------------
    def createSHFilterForSafe(onboarding_dict, session_token, store_id, safe_name):
        filter_id = ""
        url = f"https://{onboarding_dict['subdomain']}.secretshub.cyberark.cloud/api/secret-stores/{store_id}/filters"
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
                f"Filter for store ID {store_id} and safe {safe_name} created."
            )
        else:
            status_code = response.status_code
            response_body = response.text

        if DEBUG:
            print("================ createSHFilterForSafe() ================")
            print(f"\tfilter_id: {filter_id}")
            print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

        return filter_id, status_code, response_body

    # -------------------------------------------

    filter_id = ""
    status_code = 0
    safe_name = onboarding_dict["safe"]
    response_body = f"Source store filter for store ID {store_id} and safe {safe_name} retrieved successfully."

    # get all filters
    url = f"https://{onboarding_dict['subdomain']}.secretshub.cyberark.cloud/api/secret-stores/{store_id}/filters"
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
            filter_id, status_code, response_body = createSHFilterForSafe(
                onboarding_dict, session_token, store_id, safe_name
            )
        elif len(foundFilter) == 1:  # filter already exists - use it
            filter_id = foundFilter.pop()["id"]
        else:  # more than one filter exists - ambiguous
            status_code = 300
            response_body = f"More than one filter already exists for store ID {store_id} and safe {safe_name}."

    else:
        response_body = response.text

    if DEBUG:
        print("================ getSHFilterForSafe() ================")
        print(f"\tfilter_id: {filter_id}")
        print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return filter_id, status_code, response_body


# -------------------------------------------
def getSHTargetStoreId(onboarding_dict, session_token):
    # Exactly one target store for account/region must already exist in Secrets Hub.
    # Uses account and region ID from dict to find existing target store.
    # Returns tstore_id, status_code == 200 for success, response_body with message

    tstore_id = ""
    status_code = 200
    response_body = "Target store retrieved successfully"

    url = f"https://{onboarding_dict['subdomain']}.secretshub.cyberark.cloud/api/secret-stores"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.request("GET", url, headers=headers)
    status_code = response.status_code
    if status_code == 200:
        stores_dict = json.loads(response.text)
        # filter out Source & non-AWS stores because they don't have entries for AWS account/region
        isAwsTarget = lambda x: (
            (x["type"] == "AWS_ASM") & ("SECRETS_TARGET" in x["behaviors"])
        )
        allAwsTargets = [t for t in stores_dict["secretStores"] if isAwsTarget(t)]

        account_id = onboarding_dict["awsAccount"]
        region_id = onboarding_dict["awsRegion"]
        isTheTarget = lambda x: (
            (x["data"]["accountId"] == account_id)
            & (x["data"]["regionId"] == region_id)
        )
        foundTarget = [a for a in allAwsTargets if isTheTarget(a)]
        if len(foundTarget) == 0:  # target store not found - create it
            status_code = 404
            response_body = f"Target store not found for account {account_id} and region {region_id}."
        elif len(foundTarget) > 1:  # should not happen, but just in case
            status_code = 300
            response_body = f"More than one target store found for account {account_id} and region {region_id}."
        else:
            tstore_id = foundTarget.pop()["id"]
    else:
        response_body = response.text

    if DEBUG:
        print("================ getSHTargetStoreId() ================")
        print(f"\ttstore_id: {tstore_id}")
        print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return tstore_id, status_code, response_body


# -------------------------------------------
def getSHSyncPolicy(onboarding_dict, session_token, sstore_id, tstore_id, filter_id):
    # Does not assume sync policy exists in Secrets Hub.
    # Uses IDs from dict to find existing policy.
    # If policy not fount, creates it.
    # Returns policy_id, status_code == 200 or 201 for success, response_body with message

    # -------------------------------------------
    def createSHSyncPolicy(
        onboarding_dict, session_token, sstore_id, tstore_id, filter_id
    ):
        # should probably get source, target, filter names for policy name/description
        url = f"https://{onboarding_dict['subdomain']}.secretshub.cyberark.cloud/api/policies"
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

        if DEBUG:
            print("================ createSHSyncPolicy() ================")
            print(f"\tpolicy_id: {policy_id}")
            print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

        return policy_id, status_code, response_body

    # -------------------------------------------
    # begin getSHSyncPolicy()

    policy_id = ""
    status_code = 200
    response_body = "Sync policy retrieved successfully"

    url = (
        f"https://{onboarding_dict['subdomain']}.secretshub.cyberark.cloud/api/policies"
    )
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
                onboarding_dict, session_token, sstore_id, tstore_id, filter_id
            )
        elif len(foundPolicy) > 1:
            status_code = 300
            response_body = "More than one sync policy found for source ID {sstore_id}, filter ID {filter_id}, target ID {tstore_id}."
        else:
            policy_id = foundPolicy.pop()["id"]
    else:
        response_body = response.text

    if DEBUG:
        print("================ getSHSyncPolicy() ================")
        print(f"\tpolicy_id: {policy_id}")
        print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return policy_id, status_code, response_body


# -------------------------------------------
def deleteAccount(admin_dict, session_token, secret_id):
    # Uses secret_id to lookup account in vault and delete it.
    # Returns status_code == 204 for success, response_body with message

    url = f"https://{admin_dict['subdomain']}.privilegecloud.cyberark.cloud/passwordvault/api/accounts"
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
                    response_body = f"Account {account_name} in safe {safe_name} deleted successfully."
                else:
                    response_body = response.text
            case 0:
                status_code = 404
                response_body = f"No account found for secret_id: {secret_id}"
            case _:
                status_code = 409  # 409 == 'conflict'
                response_body = (
                    f"More than one account found for secret_id: {secret_id}"
                )
    else:
        response_body = (
            f"Error searching for account corresponding to secret_id: {secret_id}"
        )

    if DEBUG:
        print("================ deleteAccount() ================")
        print(f"\tsecret_id: {secret_id}")
        print(f"\tstatus_code: {status_code}\n\tresponse: {response_body}")

    return status_code, response_body


##########################################################################################
# Lambda function handler (main entrypoint)
##########################################################################################


def lambda_handler(event, context):
    prologOut(event, context)

    # Get the event body from API event
    try:
        if (event["body"]) and (event["body"] != None):
            event = json.loads(event["body"])
            print(f"Lambda triggered by API with:\n{event}")
        else:
            return {"statusCode": 502, "body": "No body in API event."}
    except KeyError:
        print(f"Lambda triggered by CloudWatch with:\n{event}")

    # Extract the event name & ID of secret from the triggering event
    event_name = event["detail"]["eventName"]
    if event_name == "CreateSecret":
        secret_id = event["detail"]["requestParameters"]["name"]
    elif event_name == "DeleteSecret":
        secret_id = event["detail"]["requestParameters"]["secretId"]
    else:
        print(f"eventName: {eventName} - no match for 'CreateSecret' or 'DeleteSecret'")
        return {"statusCode": 502, "body": f"Unsupported event name:\n{event}"}

    # Initialize a client for AWS Secrets Manager
    secrets_manager_client = boto3.client("secretsmanager")

    # Retrieve from env var the ID of ASM secret storing admin creds
    pcloud_secret_id = os.environ.get(PCLOUD_ADMIN_SECRET_ENV_VAR, None)
    if pcloud_secret_id is None:
        response_body = f"Env var '{PCLOUD_ADMIN_SECRET_ENV_VAR}' not found in lambda environment variables."
        return {"statusCode": 404, "body": response_body}

    # Get admin creds from ASM - secret holds:
    # - subdomain - subdomain of tenant URL, e.g. https://<subdomain>.cyberark.cloud/...
    # - username/password - login credentials of CyberArk Oauth2 service user identity
    # - shRoleName - name of Secrets Hub role for tenant
    admin_dict, status_code, response_body = getAsmSecretValue(
        secrets_manager_client, pcloud_secret_id
    )
    if status_code != 200:
        return {"statusCode": status_code, "body": response_body}

    # Authenticate to Privilege Cloud
    session_token, status_code, response_body = authnCyberArk(admin_dict)
    if status_code != 200:
        return {"statusCode": status_code, "body": response_body}

    # if a Delete event, delete account and exit
    if event_name == "DeleteSecret":
        status_code, response_body = deleteAccount(admin_dict, session_token, secret_id)
        return {"statusCode": status_code, "body": response_body}

    ###############
    # Onboarding workflow from here on...
    ###############

    # Validate secret is correctly tagged for onboarding
    secmeta_dict, status_code, response_body = validateSecretMetadata(
        secrets_manager_client, secret_id
    )
    if status_code != 200:
        return {"statusCode": status_code, "body": response_body}

    # Retrieve the value of the secret to onboard
    secret_dict, status_code, response_body = getAsmSecretValue(
        secrets_manager_client, secret_id
    )
    if status_code != 200:
        return {"statusCode": status_code, "body": response_body}

    # Assemble all info into a single onboarding dictionary
    secret_dict["secretId"] = secret_id
    # Add name of secret in cloud store to secret_dict
    onboarding_dict, status_code, response_body = assembleOnboardingDict(
        admin_dict, secmeta_dict, secret_dict
    )
    if status_code != 200:
        return {"statusCode": status_code, "body": response_body}

    """ Safe must already exist with admin user as member w/ Account Manager perms
    # Create safe in Privilege Cloud
    status_code, response_body = createSafe(onboarding_dict, session_token)
    if status_code != 201:
        return {"statusCode": status_code, "body": response_body}
    """

    # Onboard account into safe
    status_code, response_body = onboardAccount(onboarding_dict, session_token)
    if status_code != 201:
        return {"statusCode": status_code, "body": response_body}

    # Add Secrets Hub user to safe
    status_code, response_body = addSHUserToSafe(onboarding_dict, session_token)
    if status_code not in [201, 409]:
        return {"statusCode": status_code, "body": response_body}

    # Get Secrets Hub source store ID - store must exist
    sstore_id, status_code, response_body = getSHSourceStoreId(
        onboarding_dict, session_token
    )
    if status_code != 200:
        return {"statusCode": status_code, "body": response_body}

    # Get filter for Safe - returns existing if found, creates if not found
    filter_id, status_code, response_body = getSHFilterForSafe(
        onboarding_dict, session_token, sstore_id
    )
    if status_code not in [200, 201]:
        return {"statusCode": status_code, "body": response_body}

    # Get Secrets Hub target store ID - store must exist
    tstore_id, status_code, response_body = getSHTargetStoreId(
        onboarding_dict, session_token
    )
    if status_code != 200:
        return {"statusCode": status_code, "body": response_body}

    # Create sync policy linking Source to Target - returns existing if found, creates if not found
    policy_id, status_code, response_body = getSHSyncPolicy(
        onboarding_dict, session_token, sstore_id, tstore_id, filter_id
    )
    if status_code not in [200, 201]:
        return {"statusCode": status_code, "body": response_body}

    return {"statusCode": 200, "body": f"Secret {secret_id} onboarded successfully."}
