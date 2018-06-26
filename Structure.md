### Structure of the main alarm index ###

DRAFT

    alert = {
        "country":                  Name (2 bytes) of the country where the attacker is located
        "countryName":              Name of the country where they attacker is located
        "vulnid":                   internal ID
        "originalRequestString": '%s' % url,
        "sourceEntryAS":            AS of the attacker
        "createTime":               Time of the attack
        "clientDomain":             Marker for community or DTAG data
        "peerIdent":                Identifier of the honeypot
        "peerType":                 Type of honeypot
        "client": "-",
        "location":                 Geolocation of the attacker
        "locationDestination":      Geolocation of the target
        "sourceEntryIp":            attacking IP
        "sourceEntryPort":          attacking source port
        "additionalData":           optional additional data
        "targetEntryIp":            IP of the honeypot
        "targetEntryPort":          attacked port (service) on the honeypot
        "targetCountry":            2 byte country shortname of land the honeypot is located
        "targetCountryName": countryTargetName,
        "targetEntryAS": asnTarget,
        "username":                 username,  # for ssh sessions
        "password":                 password,  # for ssh sessions
        "login":                    loginStatus,  # for SSH sessions
        "targetport": sourceTransport, # transport protocol (udp/tcp) targetPORT > targetPROT(ocol) ;)
        "clientVersion": version,
        "sessionStart": startTime,
        "sessionEnd": endTime,
        "recievedTime": currentTime,
        "externalIP": externalIP,
        "internalIP": internalIP,
        "hostname":                 Hostname of the honeypot
        "rawhttp": rawhttp
    }

