#!/usr/bin/env python
# -*- coding: utf-8 -*-

# PEBA (Python EWS Backend API)
# v0.1 2017-06-21 - Pre Alpha!
# Author: @vorband

import xml.etree.ElementTree as ET
import hashlib
from flask import Flask, request
from pymongo import MongoClient
from elasticsearch import Elasticsearch



#################
### Configuration
#################
mongoip = "127.0.0.1"
mongoport = 27017

elasticip = "127.0.0.1"
elasticport = 9200
elasticindex = "ews3"

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
    client = MongoClient(mongoip,  mongoport)
    db = client.ews
    dbresult = db.WSUser.find_one({'peerName': username})
    if dbresult == None:
        return False
    else:
        tokenhash = hashlib.sha512(token)
        if dbresult['token'] == tokenhash.hexdigest():
                return True
        else:
            return False

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



###############
### App Routes
###############

app = Flask(__name__)

# Default webroot access
@app.route("/")
def webroot():
    return defaultResponse

# Retrieve bad IPs
@app.route("/alert/retrieveAlertsCyber", methods=['POST'])
def retrieveAlertsCyber():
    # Retrieve POST Data
    postdata = request.data.decode('utf-8')

    # Retrieve credentials from postdata
    username, password = (getCreds(postdata))
    if username == False or password == False:
        app.logger.error('Extracting username and token from postdata failed')
        return defaultResponse

    # Check if user is in MongoDB
    if authenticate(username, password) == False:
        app.logger.error("Authentication failure for user %s", username)
        return defaultResponse

    # Retrieve IPs from ElasticSearch
    es = Elasticsearch(hosts=[{'host': elasticip, 'port': elasticport}])
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
            "sourceEntryIp" ]
        })

    iplist= set([d["_source"]["sourceEntryIp"] for d in res["hits"]["hits"]])

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

    # Return XML Structure
    return iplistxml