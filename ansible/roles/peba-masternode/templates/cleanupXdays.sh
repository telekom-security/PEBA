#!/bin/bash

# let this script run once every 24h do delete alerts > X days from index .
# 0 1 * * * /pathToScript/cleanupXdays.sh

date >> /var/log/peba/indexCleanup.log
/usr/bin/curl -XDELETE {{ ELASTIC_IP }}:{{ ELASTIC_PORT }}"/%3Cews-%7Bnow%2Fd-{{ INDEX_DAYS_KEEP }}d%7D-*%3E?pretty" >>  /var/log/peba/indexCleanup.log
