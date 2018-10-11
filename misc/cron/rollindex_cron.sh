#!/bin/bash

# let this script run once every 24h to create new daily indices.
# 0 0 * * * /pathToScript/rollindex_cron.sh


##############################################################
##############################################################

#     NOTE to myself: ALL changes must be reflected in
#     /ansible/peba-masternode/templates/rollindex_cron.sh
#	  /misc/setup-es-indices.py
#	  /misc/setupES6Indices.sh

##############################################################
##############################################################


host="127.0.0.1"
port="9200"
ews_alias="ews2017.1"

# in case we want to manually define the index name
# curl -XPOST $host:$port'/ews2017.1/_rollover/%3Cews-%7Bnow%2Fd%7D-1%3E?pretty' -H 'Content-Type: application/json' -d'


curl -XPOST $host:$port/$ews_alias'/_rollover?pretty' -H 'Content-Type: application/json' -d'
{
   "conditions":{
      "max_age":"720m"
   },
   "settings":{
      "number_of_shards":5,
      "number_of_replicas":1
   },
   "mappings":{
      "Alert":{
         "properties":{
            "additionalData":{
               "type":"keyword",
               "index":"false"
            },
            "client":{
               "type":"keyword",
               "index":"false"
            },
            "clientDomain":{
               "type":"boolean",
               "index":"true"
            },
            "clientVersion":{
               "type":"keyword",
               "index":"false"
            },
            "country":{
               "type":"keyword",
               "index":"false"
            },
            "countryName":{
               "type":"keyword",
               "index":"true"
            },
            "createTime":{
               "type":"date",
               "format":"yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis",
               "index":"true"
            },
            "externalIP":{
               "type":"ip",
               "index":"false"
            },
            "hostname":{
               "type":"keyword",
               "index":"true"
            },
            "internalIP":{
               "type":"ip",
               "index":"false"
            },
            "location":{
               "type":"keyword",
               "index":"false"
            },
            "locationDestination":{
               "type":"keyword",
               "index":"false"
            },
            "login":{
               "type":"keyword",
               "index":"false"
            },
            "originalRequestString":{
               "type":"keyword",
               "index":"true"
            },
            "password":{
               "type":"keyword",
               "index":"false"
            },
            "peerIdent":{
               "type":"keyword",
               "index":"true"
            },
            "peerType":{
               "type":"keyword",
               "index":"true"
            },
            "rawhttp":{
               "type":"keyword",
               "index":"false"
            },
            "recievedTime":{
               "type":"date",
               "format":"yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis",
               "index":"true"
            },
            "sessionEnd":{
               "type":"keyword",
               "index":"false"
            },
            "sessionStart":{
               "type":"keyword",
               "index":"false"
            },
            "sourceEntryAS":{
               "type":"keyword",
               "index":"true"
            },
            "sourceEntryIp":{
               "type":"ip",
               "index":"true"
            },
            "sourceEntryPort":{
               "type":"keyword",
               "index":"false"
            },
            "targetCountry":{
               "type":"keyword",
               "index":"no"
            },
            "targetCountryName":{
               "type":"keyword",
               "index":"true"
            },
            "targetEntryAS":{
               "type":"keyword",
               "index":"false"
            },
            "targetEntryIp":{
               "type":"ip",
               "index":"true"
            },
            "targetEntryPort":{
               "type":"keyword",
               "index":"false"
            },
            "targetport":{
               "type":"keyword",
               "index":"false"
            },
            "username":{
               "type":"keyword",
               "index":"false"
            },
            "vulnid":{
               "type":"keyword",
               "index":"false"
            }
         }
      }
   }
}
'
