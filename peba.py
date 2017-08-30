#!/usr/bin/env python
# -*- coding: utf-8 -*-

# PEBA (Python EWS Backend API)
# v0.5 2017-08-25 - Beta :)
# Author: @vorband

import xml.etree.ElementTree as ET
import defusedxml.ElementTree as ETdefused

import hashlib
import json
import urllib.request, urllib.parse, urllib.error
import html
import datetime

from flask import Flask, request, abort, jsonify, Response
from flask_cors import CORS, cross_origin

from flask_elasticsearch import FlaskElasticsearch

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
cors = CORS(app, resources={r"/alert/*": {"origins": app.config['CORSDOMAIN']}})

es = FlaskElasticsearch(app,
    timeout=app.config['ELASTICTIMEOUT']
)

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
            root = ETdefused.fromstring(postdata)
            user_data = root.find("./Authentication/username")
            pass_data = root.find("./Authentication/token")

            if user_data is None or pass_data is None:
                app.logger.error('Invalid XML: token not present or empty')
                return abort(403)

            username = user_data.text
            password = pass_data.text

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
            tokenhash = hashlib.sha512(token.encode('utf-8'))
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
            "bool": {
              "must": [
                {
                  "range": {
                    "createTime": {
                        "gte": "now-%sm" % badIpTimespan
                    }
                  }
                },
                {
                  "match_all": {}
                }
              ]
            }
          },
          "aggs": {
            "ips": {
              "terms": {
                "field": "sourceEntryIp",
                "size": 1000000
              }
            }
          },
          "size": 0
        })
        return res["aggregations"]["ips"]
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
                "recievedTime": {
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
                "countryName",
                "locationDestination",
                "recievedTime",
                "username",
                "password",
                "login"
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
        span = "now-%sm" % timeframe
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

def retrieveAlertCountWithType(timeframe):
    """ Get number of Alerts in timeframe in elasticsearch """

    # check if timespan = d or number
    if timeframe == "day":
        span = "now/d"
    elif timeframe.isdecimal():
        span = "now-%sm" % timeframe
    else:
        app.logger.error('Non numeric value in retrieveAlertCountWithType timespan. Must be decimal number (in minutes) or string "day"')
        return False

    try:
        res = es.search(index=app.config['ELASTICINDEX'], body={
              "query": {
                "range": {
                  "createTime": {
                    "gte": str(span)

                  }
                }
              },
              "aggs": {
                    "honeypotTypes": {
                      "terms": {
                        "field": "peerType.keyword"


                  }
                }
              },
              "size": 0
            })
        return res
    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' %  err)

    return False


def retrieveDatasetAlertPerMonth(days):
    # check if months is a number
    if days is None:
        span = "now-1M/d"
    elif days.isdecimal():
        span = "now-%sd/d" % days
    else:
        app.logger.error('Non numeric value in datasetAlertsPerMonth timespan. Must be decimal number in days')
        return False

    try:
        res = es.search(index=app.config['ELASTICINDEX'], body={
              "query": {
                "range": {
                  "createTime": {
                    "gte": str(span)
                  }
                }
              },
              "aggs": {
                "range": {
                  "date_histogram": {
                    "field": "createTime",
                    "interval": "day"
                  }
                }
              },
              "size": 0
            })
        return res["aggregations"]["range"]
    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' %  err)

    return False

def retrieveDatasetAlertTypePerMonth(days):
    # check if days is a number
    if days is None:
        span = "now-1M/d"
    elif days.isdecimal():
        span = "now-%sd/d" % days
    else:
        app.logger.error('Non numeric value in datasetAlertsTypesPerMonth timespan. Must be decimal number in days')
        return False

    try:
        res = es.search(index=app.config['ELASTICINDEX'], body={
          "query": {
            "range": {
              "createTime": {
                "gte": span
              }
            }
          },
          "aggs": {
            "range": {
              "date_histogram": {
                "field": "createTime",
                "interval": "day"
              },
              "aggs": {
                "nested_terms_agg": {
                  "terms": {
                    "field": "peerType.keyword"
                  }
                }
              }
            }
          },
          "size": 0
        })
        return res["aggregations"]["range"]
    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' %  err)

    return False

def retrieveAlertStat():
    """ Get combined statistics from elasticsearch """
    try:
        res = es.search(index=app.config['ELASTICINDEX'], body={
          "aggs": {
            "ctr": {
              "range": {
                "field": "createTime",
                "ranges": [
                  {
                    "key": "1d",
                    "from": "now-1440m"
                  },
                  {
                    "key": "1h",
                    "from": "now-60m"
                  },
                  {
                    "key": "1m",
                    "from": "now-1m"
                  }
                ]
              }
            }
          },
          "size": 0
        })
        return res['aggregations']['ctr']['buckets']
    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' % err)

    return False

def retrieveTopCountryAttacks(monthOffset, topX):
    # use THIS month
    if monthOffset is None:
        span = "now/M"
        monthOffset = 0
    # check if months is a number
    elif monthOffset.isdecimal():
        span = "now-%sM/M" % monthOffset
    else:
        app.logger.error('Non numeric value in retrieveTopCountryAttacks monthOffset. Must be decimal number in months')
        return False

    # use top10 default
    if topX is None:
        topx = 10
    # check if months is a number
    elif topX.isdecimal():
        topx = topX
    else:
        app.logger.error(
            'Non numeric value in /retrieveTopCountryAttacks topX. Must be decimal number.')
        return False


    # Get top 10 attacker countries
    try:
        res = es.search(index=app.config['ELASTICINDEX'], body={
          "query": {
            "range": {
              "createTime": {
                "gte": span
              }
            }
          },
          "aggs": {
            "countries": {
              "terms": {
                "field": "country.keyword",
                "size" : str(topx)
              },
              "aggs": {
                "country": {
                  "top_hits": {
                    "size": 1,
                    "_source": {
                      "include": [
                        "countryName"
                      ]
                    }
                  }
                }
              }
            }
          },
          "size": 1,
          "_source": [
                "createTime"
              ]
        })
    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' % err)

    # Get top 10 attacked countries
    try:
        res2 = es.search(index=app.config['ELASTICINDEX'], body={
            "query": {
                "range": {
                    "createTime": {
                        "gte": span
                    }
                }
            },
            "aggs": {
                "countries": {
                    "terms": {
                        "field": "targetCountry.keyword",
                        "size": str(topx)
                    },
                    "aggs": {
                        "country": {
                            "top_hits": {
                                "size": 1,
                                "_source": {
                                    "include": [
                                        "targetCountryName"
                                    ]
                                }
                            }
                        }
                    }
                }
            },
            "size": 0,
            "_source": [
                "createTime"
            ]
        })
        return [ res["aggregations"]["countries"]["buckets"], monthOffset,res["hits"]["hits"][0]["_source"]["createTime"], res2["aggregations"]["countries"]["buckets"] ]
    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' % err)

    return False

def retrieveLatLonAttack(direction, topX, dayoffset):
    # use default: Lat long of source
    if direction is None:
        locationString = "location"
    elif direction == "src":
        locationString = "location"
    elif direction == "dst":
        locationString = "locationDestination"
    else:
        app.logger.error('Invalid value in /retrieveLatLonAttacks direction. Must be "src" or "dest"')
        return False

    # use top10 default
    if topX is None:
        topx = 10
        # check if months is a number
    elif topX.isdecimal():
        topx = topX
    else:
        app.logger.error(
            'Non numeric value in /retrieveLatLonAttacks topX. Must be decimal number.')
        return False

    # statistics for 24 hours
    if dayoffset is None:
        span = "now-24h"
    # check if days is a number
    elif dayoffset.isdecimal():
        span = "now-%dd" % int(dayoffset)
    else:
        app.logger.error(
            'Non numeric value in /retrieveLatLonAttacks day offset. Must be decimal number.')
        return False


    # Get location strings
    try:
        res = es.search(index=app.config['ELASTICINDEX'], body={
          "query": {
            "range": {
              "createTime": {
                "gte": dayoffset
              }
            }
          },
          "size": 1,
          "_source": [
            "location",
            "createTime"
          ],
          "aggs": {
            "topLocations": {
              "terms": {
                "field": "%s.keyword" % locationString,
                "size": str(topx)
              }
            }
          }
        })
        return [ res["aggregations"]["topLocations"]["buckets"],res["hits"]["hits"][0]["_source"]["createTime"]]
    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' % err)

    return False

# Formatting functions

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

def createBadIPxml(iplist):
    """ Create XML Strucure for BadIP list """

    if iplist:
        ewssimpleinfo = ET.Element('EWSSimpleIPInfo')
        sources = ET.SubElement(ewssimpleinfo, 'Sources')

        for ip in iplist['buckets']:
            source = ET.SubElement(sources, 'Source')
            address = ET.SubElement(source, 'Address')
            address.text = ip['key']
            counter = ET.SubElement(source, 'Count')
            counter.text = str(ip['doc_count'])


        prettify(ewssimpleinfo)
        iplistxml = '<?xml version="1.0" encoding="UTF-8"?>'
        iplistxml += (ET.tostring(ewssimpleinfo, encoding="utf-8", method="xml")).decode('utf-8')

        return Response(iplistxml, mimetype='text/xml')
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
        alertsxml += (ET.tostring(EWSSimpleAlertInfo, encoding="utf-8", method="xml")).decode('utf-8')
        return Response(alertsxml, mimetype='text/xml')
    else:
        return app.config['DEFAULTRESPONSE']

def createAlertsJson(alertslist):
    """ Create JSON Structure for Alerts list """
    if alertslist:
        jsonarray = []

        for alert in alertslist:
            if datetime.datetime.strptime(alert['_source']['createTime'], "%Y-%m-%d %H:%M:%S") > datetime.datetime.utcnow():
                returnDate = alert['_source']['recievedTime']
                app.logger.debug('createAlertsJson: createTime > now, returning recievedTime, honeypot timezone probably manually set to eastern timezone')
            else:
                returnDate = alert['_source']['recievedTime']

            latlong = alert['_source']['location'].split(' , ')
            destlatlong = alert['_source']['locationDestination'].split(' , ')

            # kippo attack details
            if alert['_source']['originalRequestString'] is not " " and alert['_source']['peerType'] == "SSH/console(cowrie)":
                requestString =  ""
                if alert['_source']['username'] is not None:
                    requestString+= "Username: \"" + str(urllib.parse.unquote(alert['_source']['username'])) + "\""
                else:
                    requestString += "Username: <none>"
                if alert['_source']['password'] is not None:
                    requestString+= " | Password: \"" + str(urllib.parse.unquote(alert['_source']['password'])) + "\""
                else:
                    requestString += " | Password: <none>"
                if alert['_source']['login'] is not None:
                    requestString+= " | Status: "+ str(alert['_source']['login'])
                requestStringOut = html.escape(requestString)
            else:
                requestStringOut = html.escape(urllib.parse.unquote(alert['_source']['originalRequestString']))

            jsondata = {
                'id': alert['_id'],
                'dateCreated': "%s" % returnDate,
                'country': alert['_source']['country'],
                'countryName': alert['_source']['countryName'],
                'targetCountry': alert['_source']['targetCountry'],
                'sourceLat': latlong[0],
                'sourceLng': latlong[1],
                'destLat' : destlatlong[0],
                'destLng' : destlatlong[1],
                'analyzerType': alert['_source']['peerType'],
                'requestString': '%s' % requestStringOut
            }

            jsonarray.append(jsondata)

        return jsonify({'alerts': jsonarray})
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
            alertcountxml += (ET.tostring(ewssimpleinfo, encoding="utf-8", method="xml")).decode('utf-8')
            return Response(alertcountxml, mimetype='text/xml')
        else:
            return jsonify({'AlertCount': numberofalerts})
    else:
        return app.config['DEFAULTRESPONSE']

def createAlertCountResponseWithType(numberofalerts):
    if numberofalerts:
        jsondata1 = {}
        for alertTypes in numberofalerts['aggregations']['honeypotTypes']['buckets']:
            jsondata1[alertTypes['key']] = alertTypes['doc_count']

        jsondata2 = {
                "AlertCountTotal" : numberofalerts['hits']['total'],
                "AlertCountPerType" : jsondata1
        }
        return jsonify(jsondata2)
    else:
        return app.config['DEFAULTRESPONSE']

def createRetrieveDatasetAlertsPerMonth(datasetAlertsPerMonth):
    if datasetAlertsPerMonth:
        jsondata = {}
        for alertsPerMonth in datasetAlertsPerMonth['buckets']:
                jsondata[alertsPerMonth['key_as_string']] = alertsPerMonth['doc_count']

        return jsonify([{'datasetAlertsPerMonth': jsondata}])
    else:
        return app.config['DEFAULTRESPONSE']

def createDatasetAlertTypesPerMonth(datasetAlertTypePerMonth):
    if datasetAlertTypePerMonth:
        jsondatamonth = {}
        for alertTypesPerMonth in datasetAlertTypePerMonth['buckets']:
            jsondatatype = {}
            for alertTypes in alertTypesPerMonth['nested_terms_agg']['buckets']:
                jsondatatype[alertTypes['key']] =  alertTypes['doc_count']
                jsondatamonth[alertTypesPerMonth['key_as_string']] = jsondatatype

        return jsonify([{'datasetAlertsPerMonth': jsondatamonth}])
    else:
        return app.config['DEFAULTRESPONSE']

def createRetrieveAlertStats(retrieveAlertStat):
    if retrieveAlertStat:
        jsondata = {
            'AlertsLast24Hours': retrieveAlertStat[0]['doc_count'],
            'AlertsLastHour': retrieveAlertStat[1]['doc_count'],
            'AlertsLastMinute': retrieveAlertStat[2]['doc_count']
        }
        return jsonify(jsondata)
    else:
        return app.config['DEFAULTRESPONSE']

def createTopCountryAttacks(retrieveTopCountryAttacksArr):
    if retrieveTopCountryAttacksArr:
        retrieveTopCountryAttacker = retrieveTopCountryAttacksArr[0]
        monthOffset = retrieveTopCountryAttacksArr[1]
        monthdate = retrieveTopCountryAttacksArr[2]
        retrieveTopCountryAttacked = retrieveTopCountryAttacksArr[3]

    else:
        return app.config['DEFAULTRESPONSE']

    # Create json structure for ATTACKER and ATTACKED countries
    if retrieveTopCountryAttacker and retrieveTopCountryAttacked:
        jsonarray_attacker = []
        jsonarray_attacked = []

        # attacker
        for topCountry in retrieveTopCountryAttacker:
            jsondata_attacker = {
                'code': topCountry['key'],
                'country': topCountry['country']['hits']['hits'][0]['_source']['countryName'],
                'count': topCountry['doc_count']
            }
            jsonarray_attacker.append(jsondata_attacker)

        # attacked
        for topCountry in retrieveTopCountryAttacked:
            jsondata_attacked = {
                'code': topCountry['key'],
                'country': topCountry['country']['hits']['hits'][0]['_source']['targetCountryName'],
                'count': topCountry['doc_count']
            }
            jsonarray_attacked.append(jsondata_attacked)

        countryStats = { 'id' :  monthOffset,
                     'date': datetime.datetime.strptime(monthdate, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m'),
                     'attacksPerCountry': jsonarray_attacker,
                     'attacksToTargetCountry': jsonarray_attacked
                         }

        return jsonify([countryStats])

    return app.config['DEFAULTRESPONSE']

def createLatLonAttacks(retrieveLatLonAttacksArr):
    if retrieveLatLonAttacksArr:
        retrieveLatLonAttacks = retrieveLatLonAttacksArr[0]
        monthdate = retrieveLatLonAttacksArr[1]


    if retrieveLatLonAttacks:

        jsonarray_location = []

        for attackLocation in retrieveLatLonAttacks:
            latLonArr = attackLocation['key'].split(" , ")
            jsondata_location = {
                'lat': latLonArr[0],
                'lng' : latLonArr[1],
                'count': attackLocation['doc_count']
            }
            jsonarray_location.append(jsondata_location)


        LatLonStats = {
                     'statsSince': datetime.datetime.strptime(monthdate, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d'),
                     'latLonAttacks': jsonarray_location
                         }


        return jsonify([LatLonStats])

    return app.config['DEFAULTRESPONSE']



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


# Routes with XML output

@app.route("/alert/retrieveIPs", methods=['POST'])
@login_required
def retrieveIPs():
    """ Retrieve IPs from ElasticSearch and return formatted XML with IPs """
    return createBadIPxml(retrieveBadIPs(app.config['BADIPTIMESPAN']))


@app.route("/alert/retrieveAlertsCyber", methods=['POST'])
@login_required
def retrieveAlertsCyber():
    """ Retrieve Alerts from ElasticSearch and return formatted 
        XML with limited alert content
    """
    return createAlertsXml(retrieveAlerts(app.config['MAXALERTS']))


# Routes with both XML and JSON output

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


# Routes with JSON output

@app.route("/alert/retrieveAlertsCountWithType", methods=['GET'])
def retrieveAlertsCountWithType():
    """ Retrieve number of alerts in timeframe (GET-Parameter time as decimal or "day") and divide into honypot types"""

    # Retrieve Number of Alerts from ElasticSearch and return as xml / json
    if not request.args.get('time'):
        app.logger.error('No time GET-parameter supplied in retrieveAlertsCountWithType. Must be decimal number (in minutes) or string "day"')
        return app.config['DEFAULTRESPONSE']
    else:
        return createAlertCountResponseWithType(retrieveAlertCountWithType(request.args.get('time')))

@app.route("/alert/retrieveAlertsJson", methods=['GET'])
def retrieveAlertsJson():
    """ Retrieve last 5 Alerts in JSON without IPs """
    # Retrieve last 5 Alerts from ElasticSearch and return JSON formatted with limited alert content
    return createAlertsJson(retrieveAlertsWithoutIP(5))

@app.route("/alert/datasetAlertsPerMonth", methods=['GET'])
def retrieveDatasetAlertsPerMonth():
    """ Retrieve the attacks / day in the last x days from elasticsearch
        and return as JSON for the last months, defaults to last month,
        if no GET parameter days is given
    """
    if not request.args.get('days'):
        # Using default : within the last month
        return (createRetrieveDatasetAlertsPerMonth(retrieveDatasetAlertPerMonth(None)))
    else:
        return createRetrieveDatasetAlertsPerMonth(retrieveDatasetAlertPerMonth(request.args.get('days')))

@app.route("/alert/datasetAlertTypesPerMonth", methods=['GET'])
def retrieveDatasetAlertTypesPerMonth():
    """ Retrieve the attacks / day in the last x days from elasticsearch,
        split by attack group
        and return as JSON for the last x months, defaults to last month,
        if no GET parameter days is given
    """
    if not request.args.get('days'):
        # Using default : within the last month
        return (createDatasetAlertTypesPerMonth(retrieveDatasetAlertTypePerMonth(None)))
    else:
        return createDatasetAlertTypesPerMonth(retrieveDatasetAlertTypePerMonth(request.args.get('days')))

@app.route("/alert/retrieveAlertStats", methods=['GET'])
def retrieveAlertStats():
    """ Retrieve combined statistics
        AlertsLastMinute, AlertsLastHour,  AlertsLast24Hours
    """
    return createRetrieveAlertStats(retrieveAlertStat())

@app.route("/alert/topCountriesAttacks", methods=['GET'])
def retrieveTopCountriesAttacks():
    """ Retrieve the Top X countries and their attacks within month
    """
    if not request.args.get('monthOffset'):
        # Using default : within the last month
        offset = None
    else:
        offset = request.args.get('monthOffset')

    if not request.args.get('topx'):
        # Using default top 10
        topx = None
    else:
        topx = request.args.get('topx')
    return createTopCountryAttacks(retrieveTopCountryAttacks(offset, topx))

@app.route("/alert/retrieveLatLonAttacks", methods=['GET'])
def retrieveLatLonAttacks():
    """ Retrieve statistics on Latitude and Longitude of the attack sources / destinations.
        offset in days
        topX determines how many
        direction src = src lat lng
        direction dst = dest lat lng
    """
    if not request.args.get('direction'):
        # Using default : lat and long of attack sources
        direction = None
    else:
        # using attack destinations
        direction = request.args.get('direction')

    if not request.args.get('topx'):
        # Using default top 10
        topx = None
    else:
        topx = request.args.get('topx')

    if not request.args.get('offset'):
        # Using default 24h
        offset = None
    else:
        offset = request.args.get('offset')

    return createLatLonAttacks(retrieveLatLonAttack(direction, topx, offset))

###############
### Main
###############

if __name__ == '__main__':
    app.run(host=app.config['BINDHOST'].split(':')[0], port=int(app.config['BINDHOST'].split(':')[1]))
