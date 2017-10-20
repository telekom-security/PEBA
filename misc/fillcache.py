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
import pylibmc
from time import sleep
import threading


#caches = [MemcachedCache(['192.168.1.64:11211']),MemcachedCache(['192.168.1.173:11211']),MemcachedCache(['192.168.1.233:11211']), MemcachedCache(['192.168.1.87:11211']), MemcachedCache(['192.168.1.152:11211']), MemcachedCache(['192.168.1.213:11211']),   ]
#caches = [MemcachedCache(['127.0.0.1:11211']),MemcachedCache(['127.0.0.1:11222'])]
#caches = pylibmc.Client(["127.0.0.1:11211","127.0.0.1:11222"], binary=False, behaviors={"tcp_nodelay": True, "ketama": True, "connect_timeout": 200})

caches = [pylibmc.Client(["127.0.0.1:11211"], binary=False, behaviors={"tcp_nodelay": True, "ketama": True, "connect_timeout": 200}), pylibmc.Client(["127.0.0.1:11222"], binary=False, behaviors={"tcp_nodelay": True, "ketama": True, "connect_timeout": 200})]
es = Elasticsearch(["127.0.0.1"])
esindex="ews2017.1"

def testElasticsearch():
    try:
        return es.ping()
    except:
        return False

def getCache(cacheItem):
    rv = cache.get(cacheItem)
    if rv is None:
        return False
    return rv

def testMemcached():
    for cache in caches:
        try:
            cache.has("heartbeat")
        except:
            return False
    return True

def setCache(cacheItem, cacheValue, cacheTimeout):
    i=0
    for cache in caches:
        i+=1
        try:
            cache.set(cacheItem, cacheValue, cacheTimeout)
        except pylibmc.Error as e:
            #print("Could not set memcache {0} cache {1}".format(i, cacheItem))
            print(e)
            return False
    return True

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
        res = es.search(index=esindex, body={
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
            if alert['_source']['peerType'] == "SSH/console(cowrie)" and alert['_source']['originalRequestString'] == "":
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


            # map private IP ranges 0:0 Locations to DTAG HQ in Bonn :) # 50.708021, 7.129191
            if latlong == ["0.0","0.0"]:
                latlong = ["50.708021", "7.129191"]
                # print('formatAlertsJson: mapping location 0.0/0.0 to DTAG HQ')

            if destlatlong == ["0.0","0.0"]:
                destlatlong = ["50.708021", "7.129191"]
                # print('formatAlertsJson: mapping location 0.0/0.0 to DTAG HQ')


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
        return ({'alerts': jsonarray})

def queryTopCountriesAttacks(monthOffset, topX, clientDomain):
    # use THIS month
    if monthOffset is None or monthOffset == "0" :
        span = "now/M"
        monthOffset = 0
        span2 = "now"
    # check if months is a number
    elif monthOffset.isdecimal():
        span = "now-%dM/M" % int(monthOffset)
        span2 = "now-%dM/M" % (int(monthOffset)-1)
    else:
        print('Non numeric value in topCountriesAttacks monthOffset. Must be decimal number in months')
        return False

    # use top10 default
    if topX is None:
        topx = 10
    # check if months is a number
    elif topX.isdecimal():
        topx = topX
    else:
        print(
            'Non numeric value in topCountriesAttacks topX. Must be decimal number.')
        return False


    # Get top 10 attacker countries
    try:
        res = es.search(index=esindex, body={
          "query": {
            "range": {
              "recievedTime": {
                "gte": span,
                "lt": span2
              }
            }
          },
            "aggs": {
                "communityfilter": {
                    "filter": {
                        "term": {
                            "clientDomain": clientDomain
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
                }}}
              }
            }
          },
          "size": 0
        })
    except ElasticsearchException as err:
        print('ElasticSearch error: %s' % err)

    # Get top 10 attacked countries
    try:
        res2 = es.search(index=esindex, body={
            "query": {
                "range": {
                    "recievedTime": {
                        "gte": span,
                        "lt": span2
                    }
                }
            },
            "aggs": {
                "communityfilter": {
                    "filter": {
                        "term": {
                            "clientDomain": clientDomain
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
                            }}}
                        }
                    }
                }
            },
            "size": 0,
            "_source": [
                "createTime"
            ]
        })

        monthData = (datetime.date.today()+ relativedelta(months=-(int(monthOffset)))).strftime('%Y-%m')
        return [ res["aggregations"]["communityfilter"]["countries"]["buckets"], monthOffset, monthData, res2["aggregations"]["communityfilter"]["countries"]["buckets"] ]
    except ElasticsearchException as err:
        print('ElasticSearch error: %s' % err)

    return False

def formatTopCountriesAttacks(retrieveTopCountryAttacksArr):
        if retrieveTopCountryAttacksArr:
            retrieveTopCountryAttacker = retrieveTopCountryAttacksArr[0]
            monthOffset = retrieveTopCountryAttacksArr[1]
            monthdate = retrieveTopCountryAttacksArr[2]
            retrieveTopCountryAttacked = retrieveTopCountryAttacksArr[3]

        else:
            return ""

        # Create json structure for ATTACKER and ATTACKED countries
        jsonarray_attacker = []
        jsonarray_attacked = []

        if retrieveTopCountryAttacker and retrieveTopCountryAttacked:

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

        countryStats = {'id': monthOffset,
                        'date': monthdate,
                        'attacksPerCountry': jsonarray_attacker,
                        'attacksToTargetCountry': jsonarray_attacked
                        }
        return ([countryStats])

def queryAlertStats(clientDomain):
    """ Get combined statistics from elasticsearch """
    try:
        res = es.search(index=esindex, body={
            "aggs": {
                "communityfilter": {
                    "filter": {
                        "term": {
                            "clientDomain": clientDomain
                        }
                    },
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
            }}}
          },
          "size": 0
        })
        return res['aggregations']['communityfilter']['ctr']['buckets']
    except ElasticsearchException as err:
        print('ElasticSearch error: %s' % err)

    return False

def formatAlertStats(retrieveAlertStat):
    if retrieveAlertStat:
        jsondata = {
            'AlertsLast24Hours': retrieveAlertStat[0]['doc_count'],
            'AlertsLastHour': retrieveAlertStat[1]['doc_count'],
            'AlertsLastMinute': retrieveAlertStat[2]['doc_count']
        }
        return (jsondata)
    else:
        return ""

def queryAlertsCountWithType(timeframe, clientDomain):
    """ Get number of Alerts in timeframe in elasticsearch """

    # check if timespan = d or number
    if timeframe == "day":
        span = "now/d"
    elif timeframe.isdecimal():
        span = "now-%sm" % timeframe
    else:
        print('Non numeric value in retrieveAlertsCountWithType timespan. Must be decimal number (in minutes) or string "day"')
        return False

    try:
        res = es.search(index=esindex, body={
          "query": {
            "range": {
              "createTime": {
                  "gte": str(span)
              }
            }
          },
          "aggs": {
            "communityfilter": {
              "filter": {
                "term": {
                  "clientDomain": clientDomain
                }
              },
              "aggs": {
                "honeypotTypes": {
                  "terms": {
                    "field": "peerType.keyword"
                  }
                }
              }
            }
          },
          "size": 0
        })
        return res
    except ElasticsearchException as err:
        print('ElasticSearch error: %s' %  err)

    return False


def formatAlertsCountWithType(numberofalerts):
    if numberofalerts:
        jsondata1 = {}
        for alertTypes in numberofalerts['aggregations']['communityfilter']['honeypotTypes']['buckets']:
            jsondata1[alertTypes['key']] = alertTypes['doc_count']

        jsondata2 = {
            "AlertCountTotal": numberofalerts['aggregations']['communityfilter']['doc_count'],
            "AlertCountPerType": jsondata1
        }
        return (jsondata2)
    else:
        return ""


########################
### string variables
########################
domain = "http://localhost:9922"
itemRetrieveAlertsJsonCommunity="/alert/retrieveAlertsJson?ci=0&topx=35"
itemRetrieveAlertsJson="/alert/retrieveAlertsJson?ci=0&topx=35"
itemTopCountriesAttacksCommunity="/alert/topCountriesAttacks?ci=1"
itemTopCountriesAttacks="/alert/topCountriesAttacks?ci=0"
itemRetrieveAlertStatsCommunity="/alert/retrieveAlertStats?ci=1"
itemRetrieveAlertStats="/alert/retrieveAlertStats?ci=0"
itemAlertsCountWithTypeCommunity="/alert/retrieveAlertsCountWithType?time=1&ci=1"
itemAlertsCountWithType="/alert/retrieveAlertsCountWithType?time=1&ci=0"


########################
### Thread Functions
#######################

# routes
## /retrieveAlertsJson
def fillCacheRetrieveAlertsJson(sleeptime, cachetime, community):
    while True:
        numAlerts = 35
        returnResult = formatAlertsJson(queryAlertsWithoutIP(numAlerts, community))
        if community == False:
            cacheItem=domain+itemRetrieveAlertsJson
        else:
            cacheItem=domain+itemRetrieveAlertsJsonCommunity
        #print("filling %s cache with response...." % cacheItem)
        settingResult=setCache(cacheItem, returnResult, cachetime)
        if not settingResult:
            print("could not successuflly set all caches %s" %cacheItem )
        sleep(sleeptime)

## /topCountriesAttacks
def fillCacheTopCountriesAttacks(sleeptime, cachetime, community):
    while True:
        returnResult = formatTopCountriesAttacks(queryTopCountriesAttacks(None, None, community))
        if community == False:
            cacheItem=domain+itemTopCountriesAttacks
        else:
            cacheItem=domain+itemTopCountriesAttacksCommunity
        #print("filling %s cache with response...." % cacheItem)
        settingResult=setCache(cacheItem, returnResult, cachetime)
        if not settingResult:
            print("could not successuflly set all caches %s" %cacheItem )

        sleep(sleeptime)


## /retrieveAlertStats
def fillRetrieveAlertStats(sleeptime, cachetime, community):
    while True:
        returnResult = formatAlertStats(queryAlertStats(community))
        if community == False:
            cacheItem=domain+itemRetrieveAlertStats
        else:
            cacheItem=domain+itemRetrieveAlertStatsCommunity
        #print("filling %s cache with response...." % cacheItem)
        settingResult=setCache(cacheItem, returnResult, cachetime)
        if not settingResult:
            print("could not successuflly set all caches %s" %cacheItem )

        sleep(sleeptime)

## /retrieveAlertsCountWithType
def fillRetrieveAlertsCountWithType(sleeptime, cachetime, community):
    while True:
        returnResult = formatAlertsCountWithType(
            queryAlertsCountWithType("1", community))
        if community == False:
            cacheItem = domain + itemAlertsCountWithType
        else:
            cacheItem = domain + itemAlertsCountWithTypeCommunity
        #print("filling %s cache with response...." % cacheItem)
        settingResult=setCache(cacheItem, returnResult, cachetime)
        if not settingResult:
            print("could not successuflly set all caches %s" %cacheItem )

        sleep(sleeptime)


########################
### Start Cache filling
#######################

if __name__ == '__main__':
    print("******** FILLING PEBA CACHE **********")
    # if not testElasticsearch():
    #     print("Elasticsearch is not accessible")
    #     exit(1)
    # if not testMemcached():
    #     print("No all configured Memcached are accessible")
    #     exit(1)


    # ## /retrieveAlertsJson
    tRetrieveAlertsJsonCommunity = threading.Thread(target=fillCacheRetrieveAlertsJson, args=(10,60,True,))
    tRetrieveAlertsJsonCommunity.start()
    tRetrieveAlertsJson = threading.Thread(target=fillCacheRetrieveAlertsJson, args=(10,60,False,))
    tRetrieveAlertsJson.start()

    ## /topCountriesAttacks
    tTopCountriesAttacksCommunity = threading.Thread(target=fillCacheTopCountriesAttacks, args=(10,60,True,))
    tTopCountriesAttacksCommunity.start()
    tTopCountriesAttacks = threading.Thread(target=fillCacheTopCountriesAttacks, args=(10,60,False,))
    tTopCountriesAttacks.start()

    # ## /retrieveAlertStats
    tRetrieveAlertStatsCommunity = threading.Thread(target=fillRetrieveAlertStats, args=(10,60,True,))
    tRetrieveAlertStatsCommunity.start()
    tRetrieveAlertStats = threading.Thread(target=fillRetrieveAlertStats, args=(10,60,False,))
    tRetrieveAlertStats.start()

    ## /retrieveAlertsCountWithType
    tRetrieveAlertsCountWithTypeCommunity = threading.Thread(target=fillRetrieveAlertsCountWithType, args=(10,60,True,))
    tRetrieveAlertsCountWithTypeCommunity.start()
    tRetrieveAlertsCountWithType = threading.Thread(target=fillRetrieveAlertsCountWithType, args=(10,60,False,))
    tRetrieveAlertsCountWithType.start()

    print(str(threading.active_count()) + " Threads started. Filling cache...")