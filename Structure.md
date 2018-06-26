### Structure of the main alarm index ###

DRAFT

    alert = {
        "country":                  "Country Code (2 bytes) of the country where the attacker is located",
        "countryName":              "Name of the country where they attacker is located",
        "vulnid":                   "CVE-ID of the attack classified, if available",
        "originalRequestString":    "Attack related information to be displayed on sicherheitstacho.eu, mostly URL of HTTP request, ssh terminal input (cowrie) or 'attack on port XXX' ",
        "sourceEntryAS":            "AS of the attacker",
        "createTime":               "Time of the attack (on the honeypot)",
        "clientDomain":             "Client domain: data generated either by community or DTAG honeypots",
        "peerIdent":                "Identifier of the honeypot (should be a uniqe id for DTAG honeypots, combined id for community honeypots",
        "peerType":                 "Type of honeypot",
        "client":,                  "Currently unused afaik",
        "location":                 "Geolocation of the attacker",
        "locationDestination":      "Geolocation of the target",
        "sourceEntryIp":            "Source IP of the attacker",
        "sourceEntryPort":          "Source port of the attacker",
        "additionalData":           "optional additional data, e.g. md5 of corresponding payloads or binaries captured",
        "targetEntryIp":            "Destination IP of the attacked honeypot daemon  - might be RFC1918 private IPs due to docker usage. If external honeypot IP needed, look at field externalIP",
        "targetEntryPort":          "Destination port on the honeypot",
        "targetCountry":            "Country Code (2 bytes) of land the honeypot is located",
        "targetCountryName":        "Name of the country the honeypot is located",
        "targetEntryAS":            "ASN of the external IP where the honeypot is located (uses targetEntryIP, might be PIR = private IP range",
        "username":                 "username e.g. for ssh sessions",
        "password":                 "password e.g. for ssh sessions",
        "login":                    "Status if ssh login was successful or not",
        "targetport":               "transport protocol (udp/tcp) never-corrected-typo: targetPORT > targetPROT(ocol) ;)",
        "clientVersion":            "SSH client version, e.g. SSH-2.0-libssh2_1.8.0",
        "sessionStart":             "Start time of ssh session (if available)",
        "sessionEnd":               "End time of ssh session (if available)",
        "recievedTime":             "Time of the attack transmission to backend (when the attack was received in the backend)",
        "externalIP":               "T-Pot 17.10 determines the external IP of the honeypot, as the targetEntryIP often shows RFC1918 private IPs ",
        "internalIP":               "internal IP address of T-Pot, e.g. when behind a NAT or local installation without public IP",
        "hostname":                 "Hostname of the honeypot, set by T-Pot 17.10 to random hostname during bootstrap",
        "rawhttp":                  "Raw http request headers in case the attack is delivered via an http request"
    }

