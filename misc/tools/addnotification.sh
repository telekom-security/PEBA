#!/usr/bin/env bash

host="127.0.0.1"
port=9200

curl -X POST "localhost:9200/ews-notifications/Notification/" -H 'Content-Type: application/json' -d'
{
    "as" : "AS3320",
    "createTime" : "2018-05-01 01:01:01",
    "email" : "abuse@telekom.de"
}
'
