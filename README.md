# Open Onboarding Automation

This is a collection of python functions to create CyberArk safes, accounts and Secrets Hub infrastructure. The functions are driven by a common provisioning request (see ./requests/*.json) that is passed as a single argument to each. The provisioning request is augmented with necessary information (session token, URL, safe name, platform id, etc.) as the workflow progresses.

The design intention is support the wide variety of workflow requirements encountered at customer sites. Therefore, it does not prescribe a rigid format for provisioning requests. It also does not require the request to contain a safe name or platform ID. Those are derived from information in the request and are easily adapted to customer naming conventions.

![json slides](https://github.com/jodyhuntatx/Onboarding-Prototype/blob/main/img/onboard-json-explainer.png?raw=true)
