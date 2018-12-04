#!/usr/bin/env python3

from elasticsearch import Elasticsearch
import json, sys
import time

host = "{{ ELASTIC_IP }}"
port = {{ ELASTIC_PORT }}
index_alias_alert = "{{ ELASTIC_INDEX }}"
index_name_cve = "ewscve"
index_name_packets = "packets"
index_name_notifications = "ews-notifications"


###

es = Elasticsearch([{'host': host, 'port': port}])

def getTargetIds(jsonData):
    data = json.loads(jsonData)
    if 'error' in data:
        return "fail"
    if 'data' not in data['to']:
        return "success"



###### Alert Index


index_body_alerts = {
    "settings": {
        "number_of_shards" : 5,
        "number_of_replicas" : 1
    },
    "aliases" : {
        index_alias_alert : {}
    },
     "mappings": {
        "Alert": {
            "properties": {
                "additionalData" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "client" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "clientDomain" : {
                    "type": "boolean",
                    "index": "true"
                },
                "clientVersion" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "country" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "countryName" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "createTime" : {
                    "type": "date",
                    "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis",
                    "index": "true"
                },
                "externalIP" : {
                    "type" : "ip",
                    "index" : "false"
                },
                "hostname" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "internalIP" : {
                    "type" : "ip",
                    "index" : "false"
                },
                "location" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "locationDestination" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                 "login" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "originalRequestString" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "password" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "peerIdent" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "peerType" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "rawhttp" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "recievedTime":{
                    "type": "date",
                    "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis",
                    "index" : "true"
                },
                 "sessionEnd" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "sessionStart" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                 "sourceEntryAS" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "sourceEntryIp" : {
                    "type" : "ip",
                    "index" : "true"
                },
                "sourceEntryPort" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "targetCountry" : {
                    "type" : "keyword",
                    "index" : "no"
                },
                "targetCountryName" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "targetEntryAS" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "targetEntryIp" : {
                    "type" : "ip",
                    "index" : "true"
                },
                "targetEntryPort" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                 "targetport":{
                    "type" : "keyword",
                    "index" : "false"
                },
                "username": {
                    "type" : "keyword",
                    "index" : "false"
                },
                 "vulnid": {
                    "type" : "keyword",
                    "index" : "false"
                }
            }
        }
    }
}

# Create Alert index if not present
if es.indices.exists(index=index_alias_alert):
    print("Alias %s already exists. Skipping!"% index_alias_alert)
else:
    res = es.indices.create(index="<ews-{now/d}-1>", ignore=400, body=index_body_alerts)
    print("Result for Alert mapping")
    print(res)


###### CVE Index


index_body_cve = {
    "settings": {
        "number_of_shards" : 5,
        "number_of_replicas" : 1
    },
     "mappings": {
        "Alert": {
            "properties": {
                "additionalData" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "client" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "clientDomain" : {
                    "type": "boolean",
                    "index": "true"
                },
                "clientVersion" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "country" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "countryName" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "createTime" : {
                    "type": "date",
                    "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis",
                    "index": "true"
                },
                "externalIP" : {
                    "type" : "ip",
                    "index" : "false"
                },
                "hostname" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "internalIP" : {
                    "type" : "ip",
                    "index" : "false"
                },
                "location" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "locationDestination" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                 "login" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "originalRequestString" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "password" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "peerIdent" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "peerType" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "recievedTime":{
                    "type": "date",
                    "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis",
                    "index" : "true"
                },
                 "sessionEnd" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "sessionStart" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                 "sourceEntryAS" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "sourceEntryIp" : {
                    "type" : "ip",
                    "index" : "true"
                },
                "sourceEntryPort" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "targetCountry" : {
                    "type" : "keyword",
                    "index" : "no"
                },
                "targetCountryName" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "targetEntryAS" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                "targetEntryIp" : {
                    "type" : "ip",
                    "index" : "true"
                },
                "targetEntryPort" : {
                    "type" : "keyword",
                    "index" : "false"
                },
                 "targetport":{
                    "type" : "keyword",
                    "index" : "false"
                },
                "username": {
                    "type" : "keyword",
                    "index" : "false"
                },
                 "vulnid": {
                    "type" : "keyword",
                    "index" : "true"
                }
            }
        }
    }
}

# Create CVE index if not present
if es.indices.exists(index=index_name_cve):
    print("Index %s already exists. Skipping!"% index_name_cve)
else:
    res = es.indices.create(index=index_name_cve, ignore=400, body=index_body_cve)
    print("Result for CVE mapping")
    print(res)



###### Packets Index


index_body_packets = {
    "settings" : {
        "number_of_shards" : 5,
        "number_of_replicas" : 1
    },
    "mappings" : {
        "Packet" : {
            "properties" :  {
                "createTime" : {
                    "type" : "date",
                    "format" : "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis",
                    "index" : "false"
                },
                "data" : {
                    "type" : "keyword",
                    "index" : "no"
                },
                "fileMagic" : {
                    "type" : "keyword",
                    "index" : "no"
                },
                "fuzzyHashCount" : {
                    "type": "keyword",
                    "index": "true"
                },
                "hash" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "hashfuzzyhttp" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "initalDestPort" : {
                    "type": "keyword",
                    "index": "false"
                },
                "initialIP" : {
                    "type" : "ip",
                    "index" : "false"
                },
                "lastSeen" : {
                    "type" : "date",
                    "format" : "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis",
                    "index" : "true"
                },
                "md5count" : {
                    "type" : "keyword",
                    "index" : "false"
                }
            }
        }
    }
}

# Create Packet index if not present
if es.indices.exists(index=index_name_packets):
    print("Index %s already exists. Skipping!"% index_name_packets)
else:
    res = es.indices.create(index=index_name_packets, ignore=400, body=index_body_packets)
    print("Result for Packet mapping")
    print(res)



###### Notification Index


index_body_notifications = {
    "settings" : {
        "number_of_shards" : 5,
        "number_of_replicas" : 1
    },
    "mappings" : {
        "Notification" : {
            "properties" :  {
                "as" : {
                    "type" : "keyword",
                    "index" : "true"
                },
                "createTime" : {
                    "type" : "date",
                    "format" : "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis",
                    "index" : "true"
                },
                "email" : {
                    "type" : "keyword",
                    "index" : "true"
                }
            }
        }
    }
}

# Create Notifications index if not present
if es.indices.exists(index=index_name_notifications):
    print("Index %s already exists. Skipping!"% index_name_notifications)
else:
    res = es.indices.create(index=index_name_notifications, ignore=400, body=index_body_notifications)
    print("Result for Notification mapping")
    print(res)


# Create User index
# This is done using "/misc/add-user.py"
