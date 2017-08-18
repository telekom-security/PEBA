#!/usr/bin/env python
# -*- coding: utf-8 -*-

# PEBA (Python EWS Backend API)
# v0.3 2017-08-17 - Devel / Alpha! :)
# Author: @vorband

import xml.etree.ElementTree as ET
import hashlib
import json

from flask import Flask, request, abort
from flask_cors import CORS, cross_origin

from flask.ext.elasticsearch import FlaskElasticsearch

from pymongo import MongoClient, errors
from elasticsearch import Elasticsearch, ElasticsearchException
from werkzeug.contrib.fixers import ProxyFix

from functools import wraps

###################
### Initialization
###################

app = Flask(__name__)
app.config.from_pyfile('/etc/ews/peba.cfg')
app.wsgi_app = ProxyFix(app.wsgi_app)

es = FlaskElasticsearch(app, {
    'timeout': app.config['ELASTICTIMEOUT']
})

client = MongoClient(
    app.config['MONGOIP'],
    app.config['MONGOPORT'],
    serverSelectionTimeoutMS=app.config['MONGOTIMEOUT']
)

###############
### Functions
###############

def login_required(f):
    """ This login decorator verifies that the correct username
        and password are sent over POST in the XML format.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        postdata = request.data.decode('utf-8')

        if len(postdata) == 0:
            app.logger.error('no xml post data in request')
            return abort(403)
        else:
            root = ET.fromstring(postdata)
            user_data = root.find("./Authentication/username")
            pass_data = root.find("./Authentication/token")

            if not user_data or not pass_data:
                app.logger.error('Invalid XML: token not present or empty')
                return abort(403)

            username = user_data.text.decode('utf-8')
            password = pass_data.text.decode('utf-8')

            if not authenticate(username, password):
                app.logger.error("Authentication failure for user %s", username)
                return abort(403)

            return f(*args, **kwargs)
        return decorated_function

def testMongo():
    try:
        client.server_info()
    except errors.ServerSelectionTimeoutError as err:
        return False

    return True

def testElasticsearch():
    return es.ping()

def authenticate(username, token):
    """ Authenticate user in mongodb """

    db = client.ews
    try:
        dbresult = db.WSUser.find_one({'peerName': username})
        if dbresult:
            tokenhash = hashlib.sha512(token)
            if dbresult['token'] == tokenhash.hexdigest():
                return True

    except errors.ServerSelectionTimeoutError as err:
        app.logger.error('MongoDB cannot be reached: %s' %  err)

    return False

def getPeerCountry(peerIdent):
    """ Find country for peer in mongodb """
    db = client.ews
    try:
        dbresult = db.peer.find_one({'ident': peerIdent})
        if dbresult:
            if "country" in dbresult and dbresult['country'] != "":
                return dbresult['country']

    except errors.ServerSelectionTimeoutError as err:
        app.logger.error('MongoDB cannot be reached: %s' % err)

    return False

def retrieveBadIPs(badIpTimespan):
    """ Get IP addresses from alerts in elasticsearch """
    try:
        res = es.search(index=app.config['ELASTICINDEX'], body={
            "query": {
                "range": {
                    "createTime": {
                        "gte": "now-%sm" % badIpTimespan
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

def retrieveAlerts(maxAlerts):
    """ Get IP addresses from alerts in elasticsearch """
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

def retrieveAlertsWithoutIP(maxAlerts):
    """ Get IP addresses from alerts in elasticsearch """
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
                "peerType",
                "country",
                "originalRequestString",
                "location",
                "targetCountry",
                "countName"
                ]
            })
        return res["hits"]["hits"]
    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' % err)

    return False

def retrieveAlertCount(timeframe):
    """ Get number of Alerts in timeframe in elasticsearch """

    # check if timespan = d or number
    if timeframe == "day":
        span = "now/d"
    elif timeframe.isdecimal():
        span = "now-%sm" % timeframe)
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

def createBadIPxml(iplist):
    """ Create XML Strucure for BadIP list """

    if iplist:
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

def createAlertsXml(alertslist):
    """ Create XML Strucure for Alerts list """

    if alertslist:
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

def createAlertsJson(alertslist):
    """ Create JSON Structure for Alerts list """
    if alertslist:
        jsonarray = []

        for alert in alertslist:
            latlong = alert['_source']['location'].split(' , ')

            jsondata = {
                'id': alert['_id'],
                'dateCreated': alert['_source']['createTime'],
                'country': alert['_source']['country'],
                'countryName': alert['_source']['countryName'],
                'targetCountry': alert['_source']['targetCountry'],
                'lat': latlong[0],
                'lng': latlong[1],
                'analyzerType': alert['_source']['peerType'],
                'requestString': alert['_source']['originalRequestString'],
            }

            jsonarray.append(jsondata)

        return json.dumps({'alert': jsonarray})
    else:
        return app.config['DEFAULTRESPONSE']

def createAlertCountResponse(numberofalerts, outformat):
    """ Create XML / Json Structure with number of Alerts in requested timespan """

    if numberofalerts:
        if outformat == "xml":
            ewssimpleinfo = ET.Element('EWSSimpleIPInfo')
            alertCount = ET.SubElement(ewssimpleinfo, 'AlertCount')
            alertCount.text = str(numberofalerts)
            prettify(ewssimpleinfo)
            alertcountxml = '<?xml version="1.0" encoding="UTF-8"?>'
            alertcountxml += (ET.tostring(ewssimpleinfo, encoding="utf-8", method="xml"))
            return alertcountxml
        else:
            return json.dumps({'AlertCount': numberofalerts)
    else:
        return app.config['DEFAULTRESPONSE']

def prettify(elem, level=0):
    """ Prettify the xml output """
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

@login_required
@app.route("/alert/retrieveIPs", methods=['POST'])
def retrieveIPs():
    """ Retrieve IPs from ElasticSearch and return formatted XML with IPs """
    return createBadIPxml(retrieveBadIPs(app.config['BADIPTIMESPAN']))

@login_required
@app.route("/alert/retrieveAlertsCyber", methods=['POST'])
def retrieveAlertsCyber():
    """ Retrieve Alerts from ElasticSearch and return formatted 
        XML with limited alert content
    """
    return createAlertsXml(retrieveAlerts(app.config['MAXALERTS']))

@app.route("/alert/retrieveAlertsJson", methods=['GET'])
# TODO: Change requesting domain to new sicherheitstacho for CORS
@cross_origin(origins="sicherheitstacho.eu", methods=['GET'])
def retrieveAlertsJson():
    """ Retrieve last 5 Alerts in JSON without IPs """
    # Retrieve last 5 Alerts from ElasticSearch and return JSON formatted with limited alert content
    return createAlertsJson(retrieveAlertsWithoutIP(5))

@app.route("/alert/retrieveAlertsCount", methods=['GET'])
def retrieveAlertsCount():
    """ Retrieve number of alerts in timeframe (GET-Parameter time as decimal or "day") """

    # Retrieve Number of Alerts from ElasticSearch and return as xml / json
    if not request.args.get('time'):
        app.logger.error('No time GET-parameter supplied in retrieveAlertsCount. Must be decimal number (in minutes) or string "day"')
        return app.config['DEFAULTRESPONSE']
    else:
        if request.args.get('out') and request.args.get('out') == 'json':
            return createAlertCountResponse(retrieveAlertCount(request.args.get('time')), 'json')
        else:
            return createAlertCountResponse(retrieveAlertCount(request.args.get('time')), 'xml')

###############
### Main
###############

if __name__ == '__main__':
    app.run(host=app.config['LISTENIP'], port=app.config['LISTENPORT'])
