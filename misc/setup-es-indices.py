from elasticsearch import Elasticsearch
import json, sys
import time


##############################################################
##############################################################

#     NOTE to myself: ALL Changes must be reflected in
#     /ansible/peba-masternode/templates/setup-es-indices.py

##############################################################
##############################################################

host = "127.0.0.1"
port = 9200
indexAlertAlias= "ews2017.1"
indexCve= "ewscve"
indexPackets = "packets"


###

es = Elasticsearch([{'host': host, 'port': 9200}])

def getTargetIds(jsonData):
    data = json.loads(jsonData)
    if 'error' in data:
        return "fail"
    if 'data' not in data['to']:
        return "success"


settings = {
    "settings": {
        "number_of_shards": 5,
        "number_of_replicas": 1
    },
    "aliases": {
        indexAlertAlias: {}
    },
    "mappings": {
        "Alert": {
            "properties": {
                "createTime": {
                    "type": "date",
                    "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                },
                "recievedTime": {
                    "type": "date",
                    "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                },
                "sourceEntryIp": {
                    "type": "ip"
                },
                "targetEntryIp": {
                    "type": "ip"
                },
                "clientDomain": {
                    "type": "boolean"
                },
                "externalIP": {
                    "type": "ip"
                },
                 "internalIP": {
                    "type": "ip"
                }
            }
        }
    }
}

if es.indices.exists(index=indexAlertAlias):
    print("Alias %s already exists. Skipping!"% indexAlertAlias)
else:
    # create index
    res = es.indices.create(index="<ews-{now/d}-1>", ignore=400, body=settings)
    print("Result for Alert mapping")
    print(res)



settings2 = {
    "settings": {
        "number_of_shards": 5,
        "number_of_replicas": 1
    },
    "mappings": {
        "CVE": {
            "properties":  {
                    "createTime": {
                        "type": "date",
                        "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                    },
                    "recievedTime": {
                        "type": "date",
                        "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                    },
                    "sourceEntryIp": {
                        "type": "ip"
                    },
                    "targetEntryIp": {
                        "type": "ip"
                    },
                    "clientDomain": {
                        "type": "boolean"
                    },
                    "externalIP": {
                        "type": "ip"
                    },
                     "internalIP": {
                        "type": "ip"
                    }
            }
        }
    }
}

if es.indices.exists(index=indexCve):
    print("Index %s already exists. Skipping!"% indexCve)
else:
    # create index for cve
    res = es.indices.create(index=indexCve, ignore=400, body=settings2)
    print("Result for CVE mapping")
    print(res)



settingsPackets = {
    "settings": {
        "number_of_shards": 5,
        "number_of_replicas": 1
    },
    "mappings": {
        "Packet": {
            "properties":  {
                    "createTime": {
                        "type": "date",
                        "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                    },
                     "initialIP": {
                        "type": "ip"
                    }
            }
        }
    }
}
if es.indices.exists(index=indexPackets):
    print("Index %s already exists. Skipping!"% indexPackets)
else:
    # create index for packets
    res = es.indices.create(index=indexPackets, ignore=400, body=settingsPackets)
    print("Result for Packet mapping")
    print(res)

