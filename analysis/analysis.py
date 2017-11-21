#!/usr/bin/env python
# -*- coding: utf-8 -*-

# script to gather analysis data from es index
# v0.1

import datetime
from elasticsearch import Elasticsearch, ElasticsearchException


########################
### INIT
#######################

esindex="ews2017.1"

es = Elasticsearch(
        ['127.0.0.1'],
        port=9200
)


########################
### Wrapper Functions
########################

def testElasticsearch():
    try:
        return es.ping()
    except:
        return False

def testDataStore():
    try:
        return True
    except:
        return False

def handleHoneypotAlerts(timeframe,clientDomain):
    ''' retrieves and stores information over timeframe in minutes and cindex'''
    res=getNumberHoneypotsAndAlerts(timeframe, clientDomain, 0)
    setAlertsOverTime(timeframe,
                      res[0],
                      res[1],
                      clientDomain)
    return True

########################
### Functions to GET data
########################

def getNumberHoneypotsAndAlerts(timeframe, clientDomain, type):
    ''' retrieves destinct number of honeypots from index'''
    type=0 # all honeypot types

    if clientDomain:
        try:
            res = es.search(index=esindex, body={
              "query": {
                "bool": {
                  "must": [
                    {
                      "term": {
                        "clientDomain": clientDomain
                      }
                    },
                    {
                      "exists": {
                        "field": "hostname.keyword"
                      }
                    }
                  ],
                  "must_not": [
                    {
                      "term": {
                        "hostname.keyword": "undefined"
                      }
                    }
                  ],
                  "filter": {
                    "range": {
                      "recievedTime": {
                        "gte": "now-" + str(timeframe) + "m"
                      }
                    }
                  }
                }
              },
              "size": 0,
              "aggs": {
                "hostnames": {
                  "terms": {
                    "field": "hostname.keyword",
                    "size": 100000,
                  }
                }
              }
            })
            return len(res['aggregations']['hostnames']['buckets']),res['hits']['total']
        except ElasticsearchException as err:
            print('ElasticSearch error: %s' % err)
    else:
        try:
            res = es.search(index=esindex, body={
                  "query": {
                    "range": {
                      "recievedTime": {
                          "gte": "now-" + str(timeframe) + "m"
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
                        "hostnames": {
                          "terms": {
                            "field": "peerIdent.keyword",
                            "size": 100000
                          }
                        }
                      }
                    }
                  },
                  "size": 0
                })
            return len(res['aggregations']['communityfilter']['hostnames']['buckets']),res['aggregations']['communityfilter']['doc_count']
        except ElasticsearchException as err:
            print('ElasticSearch error: %s' % err)
    return False

def getNumberAlerts(timeframe, clientDomain):
    ''' retrieves number of alerts from index in timeframe (minutes)'''
    try:
        res = es.search(index=esindex, body={
            "query": {
                "bool": {
                    "must": [
                        {
                            "match": {
                                "clientDomain": clientDomain
                            }
                        }
                    ],
                    "filter": [
                        {
                            "range": {
                                "createTime": {
                                    "gte": "now-"+str(timeframe)+"m"
                                }
                            }
                        }
                    ]
                }
            },
            "size": 0
        })
        return res['hits']['total']
    except ElasticsearchException as err:
        print('ElasticSearch error: %s' % err)

    return False

########################
### Functions to SET data
########################

def setAlertsOverTime(timeframe, numberHoneypots, numberAlerts, cindex):
    timestamp=datetime.datetime.now().time();
    span=timeframe
    alert_count=numberAlerts;
    honeypot_count=numberHoneypots;
    domain=cindex
    print("Timeframe: " + str(span) + "min | Number of Alerts: " +  str(alert_count)+ " | Number of Honeypots: " + str(honeypot_count) + " | cindex: " + str(cindex))

    return True



########################
### Start getting data
#######################

if __name__ == '__main__':

    if not testElasticsearch():
        print("ELASTIC SEARCH UNREACHABLE. EXITING")
        exit(1)
    if not testDataStore():
        print("DATASTORE UNREACHABLE. EXITING")
        exit(1)

    #### Retrieve Data

    # DTAG
    handleHoneypotAlerts(50, False)


    # Community
    handleHoneypotAlerts(50, True)
