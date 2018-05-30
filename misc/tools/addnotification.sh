#!/usr/bin/env bash

host="127.0.0.1"
port=9000

curl -X POST "localhost:9200/ews-notifications/Notification/" -H 'Content-Type: application/json' -d'
{
    "as" : "AS3320",
    "createTime" : "2018-05-01 01:01:01",
    "email" : "abuse@telekom.de"
}
'
more
curl -X POST "localhost:9200/ews-notifications/Notification/" -H 'Content-Type: application/json' -d'
{
    "as" : "AS8422",
    "createTime" : "2018-05-01 01:01:01",
    "email" : "abuse@netcologne.de"
}
'