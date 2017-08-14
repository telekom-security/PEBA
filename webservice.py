#!/usr/bin/env python
# -*- coding: utf-8 -*-

# PEBA (Python EWS Backend API)
# v0.3 2017-08-14 - Devel / Alpha! :)
# Author: @vorband

import xml.etree.ElementTree as ET
import hashlib
import json
from flask import Flask, request
from pymongo import MongoClient, errors
from elasticsearch import Elasticsearch, ElasticsearchException
from werkzeug.contrib.fixers import ProxyFix


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

def testMongo():
    try:
        client = MongoClient(app.config['MONGOIP'], app.config['MONGOPORT'], serverSelectionTimeoutMS=1000)
        client.server_info()
    except errors.ServerSelectionTimeoutError as err:
        return False
    return True

def testElasticsearch():
    es = Elasticsearch(hosts=[{'host': app.config['ELASTICIP'], 'port': app.config['ELASTICPORT']}], timeout=1)
    return es.ping()

# Authenticate user in mongodb
def authenticate(username, token):
    client = MongoClient(app.config['MONGOIP'],  app.config['MONGOPORT'], serverSelectionTimeoutMS=app.config['MONGOTIMEOUT'])
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

# Find country for peer in mongodb
def getPeerCountry(peerIdent):
    client = MongoClient(app.config['MONGOIP'],  app.config['MONGOPORT'], serverSelectionTimeoutMS=app.config['MONGOTIMEOUT'])
    db = client.ews
    try:
        dbresult = db.peer.find_one({'ident': peerIdent})
        if dbresult == None:
            return False
        else:
            if "country" in dbresult and dbresult['country'] != "":
                return dbresult['country']
            else:
                return False
    except errors.ServerSelectionTimeoutError as err:
        app.logger.error('MongoDB cannot be reached: %s' % err)
        return False

# Get IP addresses from alerts in elasticsearch
def retrieveBadIPs(badIpTimespan):
    es = Elasticsearch(hosts=[{'host': app.config['ELASTICIP'], 'port': app.config['ELASTICPORT']}], timeout=app.config['ELASTICTIMEOUT'])
    try:
        res = es.search(index=app.config['ELASTICINDEX'], body={
                  "query": {
                    "range": {
                      "createTime": {
                        "gte": "now-"+str(badIpTimespan)+"m"
                      }
                    }
                  },
                  "sort": {
                    "createTime": {
                      "order": "desc"
                    }
                  },
                  "_source": [
                    "sourceEntryIp"
                  ]
                })
        return set([d["_source"]["sourceEntryIp"] for d in res["hits"]["hits"]])
    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' %  err)
        return False

# Get IP addresses from alerts in elasticsearch
def retrieveAlerts(maxAlerts):
    es = Elasticsearch(hosts=[{'host': app.config['ELASTICIP'], 'port': app.config['ELASTICPORT']}], timeout=app.config['ELASTICTIMEOUT'])
    try:
        res = es.search(index=app.config['ELASTICINDEX'], body={
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
                "createTime",
                "peerIdent",
                "peerType",
                "country",
                "originalRequestString",
                "location",
                "sourceEntryIp"
              ]
        })
        return res["hits"]["hits"]
    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' %  err)
        return False

# Get number of Alerts in timeframe in elasticsearch
def retrieveAlertCount(timeframe):
    es = Elasticsearch(hosts=[{'host': app.config['ELASTICIP'], 'port': app.config['ELASTICPORT']}], timeout=app.config['ELASTICTIMEOUT'])
    # check if timespan = d or number
    if timeframe == "day":
        span = "now/d"
    elif timeframe.isdecimal():
        span = "now-"+str(timeframe)+"m"
    else:
        app.logger.error('Non numeric value in retrieveAlertsCount timespan. Must be decimal number (in minutes) or string "day"')
        return False
    try:
        res = es.count(index=app.config['ELASTICINDEX'], body={
                  "query": {
                    "range": {
                      "createTime": {
                        "gte": str(span)
                      }
                    }
                  }
                })
        return res["count"]
    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' %  err)
        return False

# Create XML Strucure for BadIP list
def createBadIPxml(iplist):
    if iplist is not False:
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
        return app.config['DEFAULTRESPONSE']

# Create XML Strucure for Alerts list
def createAlertsXml(alertslist):
    if alertslist is not False:
        EWSSimpleAlertInfo = ET.Element('EWSSimpleAlertInfo')
        alertsElement = ET.SubElement(EWSSimpleAlertInfo, 'Alerts')
        for alert in alertslist:
            alertElement = ET.SubElement(alertsElement, 'Alert')
            alertId = ET.SubElement(alertElement, 'Id')
            alertId.text = alert['_id']
            alertDate = ET.SubElement(alertElement, 'DateCreated')
            alertDate.text = alert['_source']['createTime']
            peerElement = ET.SubElement(alertElement, 'Peer')
            peerId = ET.SubElement(peerElement, 'Id')
            peerId.text = alert['_source']['peerIdent']
            peerType = ET.SubElement(peerElement, 'Type')
            peerType.text = alert['_source']['peerType']
            peerCountry = ET.SubElement(peerElement, 'Country')
            peerCountry.text = getPeerCountry(alert['_source']['peerIdent'])
            requestElement = ET.SubElement(alertElement, 'Request')
            requestElement.text = alert['_source']['originalRequestString']
            sourceElement = ET.SubElement(alertElement, 'Source')
            sourceAddress = ET.SubElement(sourceElement, 'Address')
            sourceAddress.text = alert['_source']['sourceEntryIp']
            sourceCountry = ET.SubElement(sourceElement, 'Country')
            sourceCountry.text = alert['_source']['country']
            sourceCoordinates = alert['_source']['location'].split(',')
            sourceLatitude = ET.SubElement(sourceElement, 'Latitude')
            sourceLatitude.text = sourceCoordinates[0].strip()
            sourceLongitude = ET.SubElement(sourceElement, 'Longitude')
            sourceLongitude.text = sourceCoordinates[1].strip()
        prettify(EWSSimpleAlertInfo)
        alertsxml = '<?xml version="1.0" encoding="UTF-8"?>'
        alertsxml += (ET.tostring(EWSSimpleAlertInfo, encoding="utf-8", method="xml"))
        return alertsxml
    else:
        return app.config['DEFAULTRESPONSE']

# Create XML / Json Structure with number of Alerts in requested timespan
def createAlertCountResponse(numberofalerts, outformat):
    if numberofalerts is not False:
        if outformat == "xml":
            ewssimpleinfo = ET.Element('EWSSimpleIPInfo')
            alertCount = ET.SubElement(ewssimpleinfo, 'AlertCount')
            alertCount.text = str(numberofalerts)
            prettify(ewssimpleinfo)
            alertcountxml = '<?xml version="1.0" encoding="UTF-8"?>'
            alertcountxml += (ET.tostring(ewssimpleinfo, encoding="utf-8", method="xml"))
            return alertcountxml
        else:
            jsondata = {}
            jsondata['AlertCount'] = numberofalerts
            return json.dumps(jsondata)
    else:
        return app.config['DEFAULTRESPONSE']

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
app.config.from_pyfile('webservice.cfg')
app.wsgi_app = ProxyFix(app.wsgi_app)

###############
### App Routes
###############

# Default webroot access
@app.route("/")
def webroot():
    return app.config['DEFAULTRESPONSE']

# Heartbeat
@app.route("/heartbeat", methods=['GET'])
def heartbeat():
    mongoAvailable = testMongo()
    elasticsearchAvailable = testElasticsearch()
    if mongoAvailable and elasticsearchAvailable:
        return "me"
    elif mongoAvailable and not elasticsearchAvailable:
        return "m"
    elif not mongoAvailable and elasticsearchAvailable:
        return "e"
    else:
        return "flatline"



# Retrieve bad IPs
@app.route("/alert/retrieveIPs", methods=['POST'])
def retrieveIPs():
    # Retrieve POST Data and extract credentials
    username, password = (getCreds(request.data.decode('utf-8')))
    if username == False or password == False:
        app.logger.error('Extracting username and token from postdata failed')
        return app.config['DEFAULTRESPONSE']

    # Check if user is in MongoDB
    if authenticate(username, password) == False:
        app.logger.error("Authentication failure for user %s", username)
        return app.config['DEFAULTRESPONSE']

    # Retrieve IPs from ElasticSearch and return formatted XML with IPs
    return createBadIPxml(retrieveBadIPs(app.config['BADIPTIMESPAN']))


# Retrieve Alerts
@app.route("/alert/retrieveAlertsCyber", methods=['POST'])
def retrieveAlertsCyber():
    # Retrieve POST Data and extract credentials
    username, password = (getCreds(request.data.decode('utf-8')))
    if username == False or password == False:
        app.logger.error('Extracting username and token from postdata failed')
        return app.config['DEFAULTRESPONSE']

    # Check if user is in MongoDB
    if authenticate(username, password) == False:
        app.logger.error("Authentication failure for user %s", username)
        return app.config['DEFAULTRESPONSE']

    # Retrieve Alerts from ElasticSearch and return formatted XML with limited alert content
    return createAlertsXml(retrieveAlerts(app.config['MAXALERTS']))

# Retrieve Number of Alerts in timeframe (GET-Parameter time as decimal or "day")
@app.route("/alert/retrieveAlertsCount", methods=['POST'])
def retrieveAlertsCount():
    # Retrieve POST Data and extract credentials
    username, password = (getCreds(request.data.decode('utf-8')))
    if username == False or password == False:
        app.logger.error('Extracting username and token from postdata failed')
        return app.config['DEFAULTRESPONSE']

    # Check if user is in MongoDB
    if authenticate(username, password) == False:
        app.logger.error("Authentication failure for user %s", username)
        return app.config['DEFAULTRESPONSE']

    # Retrieve Number of Alerts from ElasticSearch and return as xml / json
    if not request.args.get('time'):
        app.logger.error('No time GET-parameter supplied in retrieveAlertsCount. Must be decimal number (in minutes) or string "day"')
        return app.config['DEFAULTRESPONSE']
    else:
        if request.args.get('out') and request.args.get('out') == "json":
            return createAlertCountResponse(retrieveAlertCount(request.args.get('time')), "json")
        else:
            return createAlertCountResponse(retrieveAlertCount(request.args.get('time')), "xml")



###############
### Main
###############

if __name__ == '__main__':
    app.run()
