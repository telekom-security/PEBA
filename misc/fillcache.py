#!/usr/bin/env python
# -*- coding: utf-8 -*-


import xml.etree.ElementTree as ET
import defusedxml.ElementTree as ETdefused

import hashlib
import json
import urllib.request, urllib.parse, urllib.error
import html
import datetime
from dateutil.relativedelta import relativedelta

from flask import Flask, request, abort, jsonify, Response
from flask_cors import CORS, cross_origin
from flask_elasticsearch import FlaskElasticsearch

from elasticsearch import Elasticsearch, ElasticsearchException
from werkzeug.contrib.fixers import ProxyFix

from functools import wraps
from werkzeug.contrib.cache import MemcachedCache
from time import sleep

cache = MemcachedCache(['127.0.0.1:11211'])
es = Elasticsearch()
app = Flask('fillcache')
app.config['JSON_AS_ASCII'] = True


def getCache(cacheItem):
    rv = cache.get(cacheItem)
    if rv is None:
        return False
    return rv

def setCache(cacheItem, cacheValue, cacheTimeout):
    try:
        cache.set(cacheItem, cacheValue, timeout=cacheTimeout)
    except:
        print("Could not set memcache cache {0} to value {1} and Timeout {2}".format(cacheItem, cacheValue, cacheTimeout))

def checkCommunityIndex(request):
    """check if request is agains community index or production index"""
    if not request.args.get('ci'):
        return True
    elif request.args.get('ci') == "0":
        return False
    return True

def queryAlertsWithoutIP(maxAlerts, clientDomain):
    """ Get IP addresses from alerts in elasticsearch """
    try:
        res = es.search(index="ews2017.1", body={
            "query": {
                "match": {
                    "clientDomain": clientDomain
                }
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
        print('ElasticSearch error: %s' % err)

    return False

def formatAlertsJson(alertslist):
    """ Create JSON Structure for Alerts list """
    jsonarray = []

    if alertslist:

        for alert in alertslist:
            if datetime.datetime.strptime(alert['_source']['createTime'], "%Y-%m-%d %H:%M:%S") > datetime.datetime.utcnow():
                returnDate = alert['_source']['recievedTime']
                format('formatAlertsJson: createTime > now, returning recievedTime, honeypot timezone probably manually set to eastern timezone')
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
        return json.dumps({'alerts': jsonarray})





while True:
    returnResult = formatAlertsJson(queryAlertsWithoutIP(5, True))
    print("filling cache with response....")
    setCache("/alert/retrieveAlertsJson", returnResult, 10)
    #print(returnResult)
    #print("#######")
    cacheResult=getCache("/alert/retrieveAlertsJson")
    #print(cacheResult)
    #print(type(returnResult))
    if str(cacheResult) in str(returnResult):
        print("storage successful")
    sleep(1)
