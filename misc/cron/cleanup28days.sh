#!/bin/bash

# let this script run once every 24h do delete alerts > 28days from index .
# 0 1 * * * /pathToScript/cleanup28days.sh

/usr/bin/curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d  '{"query": {"bool": {"must": [{"range": {"recievedTime": {"lte": "now-28d"}}}]}}}' "http://192.168.1.64:9200/ews2017.1/Alert/_delete_by_query" >>  /var/log/peba/cleanup_28days.log
date >> /var/log/peba/cleanup_28days.log