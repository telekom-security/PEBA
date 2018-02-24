#!/bin/bash

# let this script run once every 24h to create new daily indices.
# 0 0 * * * /pathToScript/rollindex_cron.sh

host="127.0.0.1"
port="9200"

curl -XPOST $host:$port'/ews2017.1/_rollover?pretty' -H 'Content-Type: application/json' -d'
{
  "conditions": {
    "max_age":   "2m"
  },
  "settings": {
        "number_of_shards": 5,
        "number_of_replicas": 1
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
