#!/usr/bin/env bash

curl -XPUT 'localhost:9200/ews2017.1?pretty' -H 'Content-Type: application/json' -d'
{
    "settings" : {
        "index" : {
            "number_of_shards" : 5,
            "number_of_replicas" : 1
        }
    }
}
'

curl -XPUT 'localhost:9200/ewscve?pretty' -H 'Content-Type: application/json' -d'
{
    "settings" : {
        "index" : {
            "number_of_shards" : 5,
            "number_of_replicas" : 1
        }
    }
}
'

./addmapping.sh