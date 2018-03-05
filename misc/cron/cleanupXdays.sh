#!/bin/bash

# let this script run once every 24h do delete alerts > X days from index .
# 0 1 * * * /pathToScript/cleanupXdays.sh



##############################################################
##############################################################

#     NOTE to myself: ALL changes must be reflected in
#     /ansible/peba-masternode/templates/cleanupXdays.py

##############################################################
##############################################################


days=28

/usr/bin/curl -XDELETE "http://localhost:9200/%3Cews-%7Bnow%2Fd-"$days"d%7D-*%3E?pretty" >>  /var/log/peba/indexCleanup.log
date >> /var/log/peba/indexCleanup.log