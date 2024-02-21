# Open Onboarding Automation

This is a collection of python functions to create CyberArk safes, accounts and Secrets Hub infrastructure. The functions are driven by a common provisioning request (see ./requests/*.json) that is passed as a single argument to each. The provisioning request is augmented with necessary information (session token, URL, safe name, platform id, etc.) as the workflow progresses.

The design intention is support the wide variety of workflow requirements encountered at customer sites. Therefore, it does not prescribe a rigid format for provisioning requests. It also does not require the request to contain a safe name or platform ID. Those are derived from information in the request and are easily adapted to customer naming conventions.

Admin credentials are currently passed as environment variables (see ./src/getAuthCreds.py) and only supports CyberArk Identity oauth2 service users:
 - CYBR_SUBDOMAIN - subdomain of your CyberArk tenant
 - CYBR_USERNAME - name of oauth2 service user
 - CYBR_PASSWORD - password of oauth2 service user

![safe-request](https://github.com/jodyhuntatx/Onboarding-Prototype/blob/main/img/safe-request.png?raw=true)
![acct-request](https://github.com/jodyhuntatx/Onboarding-Prototype/blob/main/img/acct-request.png?raw=true)
![platforms](https://github.com/jodyhuntatx/Onboarding-Prototype/blob/main/img/platforms.png?raw=true)
![safenamerules](https://github.com/jodyhuntatx/Onboarding-Prototype/blob/main/img/safenamerules.png?raw=true)
![all-in-one](https://github.com/jodyhuntatx/Onboarding-Prototype/blob/main/img/all-in-one.png?raw=true)
