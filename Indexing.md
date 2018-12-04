# Documentation of the Elasticsearch indexing and field types

## Background

Only indexed fields can be queried. Depending on the analyzer and the amount of data, 
indexing can be very CPU-intensive. You should only index fields that you'll query later.
indexing can be controlled by `"index": "true/false"` when setting up the index.
See: [https://www.elastic.co/guide/en/elasticsearch/guide/current/inverted-index.html](https://www.elastic.co/guide/en/elasticsearch/guide/current/inverted-index.html)

Analyzing will normalize field data before it gets written into the index to make searching
more accurate. This task is quite ressource intensive aswell. If you know what's inside the
fields of your index, you might want to disable analyzing or use the `keyword` field type
which won't get analyzed. Hence you can only search with unnormalized queries.
See: [https://www.elastic.co/guide/en/elasticsearch/guide/2.x/analysis-intro.html](https://www.elastic.co/guide/en/elasticsearch/guide/2.x/analysis-intro.html)

This document describes our best practice regarding analyzing and indexing and serves as a
template for setting up indices in `setup-es-indices.py` and `rollindex_cron.sh`

## About the `string` type
The `string` field type is deprecated: [https://www.elastic.co/blog/strings-are-dead-long-live-strings](https://www.elastic.co/blog/strings-are-dead-long-live-strings)

## Syntax of this Document
Fields are shown in descending alphabetical order
`"<field name>" : "<field type>,<indexing>"`

### Alert Index
#### Name: `ews2017.1` (daily alias for `ews-<year>.<month>.<day>-1`)
```json
{
	"additionalData" :		"keyword,no",
	"client" :			"keyword,no",
	"clientDomain" :		"bool,yes",
	"clientVersion" :		"keyword,no",
	"country" :			"keyword,no",
	"countryName" :			"keyword,yes",
	"createTime" :			"date,yes",
	"externalIP" :			"ip,no",
	"hostname" :			"keyword,yes",
	"internalIP" :			"ip,no",
	"location" :			"keyword,no",
	"locationDestination" :		"keyword,no",
	"login" :			"keyword,no",
	"originalRequestString" :	"keyword,yes",
	"password" :			"keyword,no",
	"peerIdent" :			"keyword,yes",
	"peerType" :			"keyword,yes",
	"rawhttp" :			"keyword,no",
	"recievedTime" :		"date,yes",
	"sessionEnd" :			"keyword,no",
	"sessionStart" :		"keyword,no",
	"sourceEntryAS" :		"keyword,yes",
	"sourceEntryIp" :		"ip,yes",
	"sourceEntryPort" :		"keyword,no",
	"targetCountry" :		"keyword,no",
	"targetCountryName" :		"keyword,yes",
	"targetEntryAS" :		"keyword,no",
	"targetEntryIp" :		"ip,yes",
	"targetEntryPort" :		"keyword,no",
	"targetport" :			"keyword,no",
	"username" :			"keyword,no",
	"vulnid" :			"keyword,no"
}
```
### CVE Index 
#### Name: `ewscve`

Similar to the alert index (see above), only exception is the `rawhttp`-field which is missing here

### Packet Index 
#### Name: `payloads`
```json
{
	"createTime" :			"date,no",
	"data" :			"keyword,no",
	"fileMagic" :			"keyword,no",
	"fuzzyHashCount" :		"keyword,yes",
	"hash" :			"keyword,yes",
	"hashfuzzyhttp" :		"keyword,no",
	"initalDestPort" :		"keyword,no",
	"initialIP" :			"ip,no",
	"lastSeen" :			"date,yes",
	"md5count" :			"keyword,no"
}
``` 

### Notification Index
#### Name: `ews-notifications`
```json
{
	"as" :				"Unkown",
	"createTime" :			"Unkown",
	"email" :			"Unkown"
}
```
### Users Index
#### Name: `users`
```json
{
	"getOnly" :			"Unkown",
	"community" :			"Unkown",
	"peerName" :			"Unkown",
	"email" :			"Unkown",
	"token" :			"Unkown"
}
```
