#!/usr/bin/env bash

host="127.0.0.1"
port=9200
indexAlerts="ews2017.1"
indexCve="ewscve"
indexPackets="packets"

#
# Create alerts index
#

curl -XPUT "http://"$host":"$port"/"$indexAlerts"?pretty" -H 'Content-Type: application/json' -d'
{
    "settings" : {
        "number_of_shards" : 5,
        "number_of_replicas" : 1
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
'



#
# Create cve index
#

curl -XPUT "http://"$host":"$port"/"$indexCve"?pretty" -H 'Content-Type: application/json' -d'
{
    "settings" : {
        "index" : {
            "number_of_shards" : 5,
            "number_of_replicas" : 1
        }
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
'

#
# Create packet index
#

curl -XPUT "http://"$host":"$port"/"$indexPackets"?pretty" -H 'Content-Type: application/json' -d'
{
    "settings" : {
        "index" : {
            "number_of_shards" : 5,
            "number_of_replicas" : 1
        }
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
'
