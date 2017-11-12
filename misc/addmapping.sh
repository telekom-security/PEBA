#!/usr/bin/env bash

#
# adds mapping, which have been not existing in the first versions
#



curl -XPUT 'localhost:9200/ews2017.1/_mapping/Alert?pretty' -H 'Content-Type: application/json' -d'
{
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
                    },
                     "hostname": {
                        "type": "text"
                    }
  }
}
'

curl -XPUT 'localhost:9200/ews2017.1/_mapping/IP?pretty' -H 'Content-Type: application/json' -d'
{
  "properties": {
                    "ip": {
                        "type": "ip"
                    },
                    "longitude": {
                        "type": "text"
                    },
                    "latitude": {
                        "type": "text"
                    },
                    "asn": {
                        "type": "text"
                    },
                    "country": {
                        "type": "text"
                    },
                    "countyname": {
                        "type": "text"
                    }
  }
}
'



curl -XPUT 'localhost:9200/ewscve/_mapping/CVE?pretty' -H 'Content-Type: application/json' -d'
{
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
                    },
                     "hostname": {
                        "type": "text"
                    }
  }
}
'