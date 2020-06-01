# Documentation of all Elasticsearch indices
Please see Indexing.md aswell

## Syntax of this Document
`"<field name>" : "<description>"`

### Alert Index
#### Name: `ews2017.1` (daily alias for `ews-<year>.<month>.<day>-1`)
```json
{
	"additionalData" :		"Optional additional data, e.g. md5 of corresponding payloads or binaries captured",
	"client" :			"Unkown",
	"clientDomain" :		"Client domain: data generated either by community or DTAG honeypots",
	"clientVersion" :		"SSH client version, e.g. SSH-2.0-libssh2_1.8.0",
	"country" :			"Country Code (2 bytes) of the country where the attacker is located",
	"countryName" :			"Name of the country where they attacker is located",
	"createTime" :			"Time of the attack (on the honeypot)",
	"externalIP" :			"T-Pot 17.10 determines the external IP of the honeypot, as the targetEntryIP often shows RFC1918 private IPs ",
	"hostname" :			"Hostname of the honeypot, set by T-Pot 17.10 to random hostname during bootstrap",
	"internalIP" :			"internal IP address of T-Pot, e.g. when behind a NAT or local installation without public IP",
	"location" :			"Geolocation of the attacker",
	"locationDestination" :		"Geolocation of the target",
	"login" :			"Status if ssh login was successful or not",
	"originalRequestString" :	"Attack related information to be displayed on sicherheitstacho.eu, mostly URL of HTTP request, ssh terminal input (cowrie) or 'attack on port XXX' ",
	"password" :			"password e.g. for ssh sessions",
	"peerIdent" :			"Identifier of the honeypot (should be a uniqe id for DTAG honeypots, combined id for community honeypots",
	"peerType" :			"Type of honeypot",
	"rawhttp" :			"Raw http request headers in case the attack is delivered via an http request",
	"recievedTime" :		"Time of the attack transmission to backend (when the attack was received in the backend)",
	"sessionEnd" :			"End time of ssh session (if available)",
	"sessionStart" :		"Start time of ssh session (if available)",
	"sourceEntryAS" :		"AS of the attacker",
	"sourceEntryIp" :		"Source IP of the attacker",
	"sourceEntryPort" :		"Source port of the attacker",
	"targetCountry" :		"Country Code (2 bytes) of land the honeypot is located",
	"targetCountryName" :		"Name of the country the honeypot is located",
	"targetEntryAS" :		"ASN of the external IP where the honeypot is located (uses targetEntryIP, might be PIR = private IP range",
	"targetEntryIp" :		"Destination IP of the attacked honeypot daemon  - might be RFC1918 private IPs due to docker usage. If external honeypot IP needed, look at field externalIP",
	"targetEntryPort" :		"Destination port on the honeypot",
	"targetport" :			"transport protocol (udp/tcp) never-corrected-typo: targetPORT > targetPROT(ocol) ;)",
	"username" :			"username e.g. for ssh sessions",
	"vulnid" :			"CVE-ID of the attack classified, if available"
}
```
### CVE Index 
#### Name: "ewscve"

Similar to the alert index (see above), only exception is the "rawhttp"-field which is missing here

### Packet Index 
#### Name: "packets"
```json
{
	"createTime" :			"Unkown",
	"data" :			"Unkown",
	"fileMagic" :			"Unkown",
	"fuzzyHashCount" :		"Unkown",
	"hash" :			"Unkown",
	"hashfuzzyhttp" :		"Unkown",
	"initalDestPort" :		"Unkown",
	"initialIP" :			"Unkown",
	"lastSeen" :			"Unkown",
	"md5count" :			"Unkown"
}
```
### Notification Index
#### Name: "ews-notifications"
```json
{
	"as" :				"Unkown",
	"createTime" :			"Unkown",
	"email" :			"Unkown"
}
```
### Users Index
#### Name: "users"
```json
{
	"getOnly" :			"Unkown",
	"community" :			"Unkown",
	"peerName" :			"Unkown",
	"email" :			"Unkown",
	"token" :			"Unkown"
}
```
