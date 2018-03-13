#!/bin/bash

NEWINDEXNAME="metoo2"
OLDINDEXNAME="metoo"
ALIASNAME="testindex"
ES="localhost:9200"


echo "Perparing new index $NEWINDEXNAME"
echo "+++++++++++++++++++++++++++++++++"

curl -X PUT "$ES/$NEWINDEXNAME?pretty" -d '{
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
}'



echo "Changing alias $ALIASNAME from $OLDINDEXNAME to $NEWINDEXNAME"
echo "+++++++++++++++++++++++++++++++++"


curl -X PUT "$ES/$NEWINDEXNAME/_aliases?pretty" -d '
{
    "actions": [
        { "add": {
            "alias": "'$ALIASNAME'",
            "index": "'$NEWINDEXNAME'"
        }}
    ]
}'

curl -X PUT "$ES/$OLDINDEXNAME/_aliases?pretty" -d '
{
    "actions": [
        { "remove": {
            "alias": "'$ALIASNAME'",
            "index": "'$OLDINDEXNAME'"
        }}
    ]
}'

exit 0

### delete disabled by default

echo "Deleting old index $OLDINDEXNAME"
echo "+++++++++++++++++++++++++++++++++"

curl -XDELETE "$ES/$OLDINDEXNAME?pretty"
