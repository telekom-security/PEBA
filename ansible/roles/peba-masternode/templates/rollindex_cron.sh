#!/bin/bash

# let this script run once every 24h to create new daily indices.
# 0 0 * * * /pathToScript/rollindex_cron.sh

curl -XPOST {{ ELASTIC_IP }}:{{ ELASTIC_PORT }}/{{ ELASTIC_INDEX }}'/_rollover?pretty' -H 'Content-Type: application/json' -d'
{
  "conditions": {
    "max_age":   "720m"
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
