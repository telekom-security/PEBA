#!/usr/bin/env python
# -*- coding: utf-8 -*-

# PEBA (Python EWS Backend API)
# v0.2 2017-06-22 - Alpha! :)
# Author: @vorband

import xml.etree.ElementTree as ET
import hashlib
from flask import Flask, request
from pymongo import MongoClient, errors
from elasticsearch import Elasticsearch, ElasticsearchException
from werkzeug.contrib.fixers import ProxyFix



#################
### Configuration
#################
mongoip = "127.0.0.1"
mongoport = 27017
mongoDBtimeout = 10       # Timeout for mongoDB connection

elasticip = "127.0.0.1"
elasticport = 9200
elasticindex = "ews3"
elasticTimeout = 10       # Timeout for elasticsearch connection

maxAlerts = 1000            # maximum alerts to be considered
defaultResponse = ""        # empty reponse for unsuccessful requests


###############
### Functions
###############

# Extract crendetials from request
def getCreds(postdata):
    # no post data given
    if len(postdata) == 0:
        app.logger.error('no xml post data in request')
        return False, False
    else:
        # Validate credentials in XML
        root = ET.fromstring(postdata)
        if root.find("./Authentication/username") is None or root.findtext("./Authentication/username") == "":
            app.logger.error('Invalid XML: username not present or empty')
            return False, False
        elif root.find("./Authentication/token") is None or root.findtext("./Authentication/token") == "":
            app.logger.error('Invalid XML: token not present or empty')
            return False, False
        else:
            username = root.find("./Authentication/username").text.decode('utf-8')
            password = root.find("./Authentication/token").text.decode('utf-8')
        return username, password

# Authenticate user in mongodb
def authenticate(username, token):
    client = MongoClient(mongoip,  mongoport, serverSelectionTimeoutMS=mongoDBtimeout)
    db = client.ews
    try:
        dbresult = db.WSUser.find_one({'peerName': username})
        if dbresult == None:
            return False
        else:
            tokenhash = hashlib.sha512(token)
            if dbresult['token'] == tokenhash.hexdigest():
                    return True
            else:
                return False
    except errors.ServerSelectionTimeoutError as err:
        app.logger.error('MongoDB cannot be reached: %s' %  err)
        return False

# get IP addresses from alerts in elasticsearch
def retrieveBadIPs(maxAlerts):
    es = Elasticsearch(hosts=[{'host': elasticip, 'port': elasticport}], timeout=elasticTimeout)
    try:
        res = es.search(index=elasticindex, body={
            "query": {
                "match_all": {}
            },
            "sort": {
                "createTime": {
                    "order": "desc"
                }
            },
            "size": maxAlerts,
            "_source": [
                "sourceEntryIp"]
        })
        return set([d["_source"]["sourceEntryIp"] for d in res["hits"]["hits"]])
    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' %  err)
        return False

def createBadIPxml(iplist):
    if iplist is not False:
        # Create XML Strucure
        ewssimpleinfo = ET.Element('EWSSimpleIPInfo')
        sources = ET.SubElement(ewssimpleinfo, 'Sources')
        for ip in iplist:
            source = ET.SubElement(sources, 'Source')
            address = ET.SubElement(source, 'Address')
            address.text = ip
        prettify(ewssimpleinfo)
        iplistxml = '<?xml version="1.0" encoding="UTF-8"?>'
        iplistxml += (ET.tostring(ewssimpleinfo, encoding="utf-8", method="xml"))
        return iplistxml
    else:
        return defaultResponse

# Prettify the xml output
def prettify(elem, level=0):
    i = "\n" + level*"  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            prettify(elem, level+1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i



###################
### Initialization
###################

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

###############
### App Routes
###############

# Default webroot access
@app.route("/")
def webroot():
    return defaultResponse


# Retrieve bad IPs
@app.route("/alert/retrieveAlertsCyber", methods=['POST'])
def retrieveAlertsCyber():
    # Retrieve POST Data and extract credentials
    username, password = (getCreds(request.data.decode('utf-8')))
    if username == False or password == False:
        app.logger.error('Extracting username and token from postdata failed')
        return defaultResponse

    # Check if user is in MongoDB
    if authenticate(username, password) == False:
        app.logger.error("Authentication failure for user %s", username)
        return defaultResponse

    # Retrieve IPs from ElasticSearch and return formatted XML with IPs
    return createBadIPxml(retrieveBadIPs(maxAlerts))


###############
### Main
###############

if __name__ == '__main__':
    app.run()
