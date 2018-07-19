#!/usr/bin/env python
# -*- coding: utf-8 -*-

# module to gather t-pot installation data
# v0.1

import datetime
from elasticsearch import Elasticsearch, ElasticsearchException
import ipaddress


########################
### Functions to GET data
########################

def getNumberHoneypotsAndAlerts(app, clientDomain, es, esindex, utcTimeFrom, utcTimeTo):
    ''' retrieves destinct number of honeypots from index'''
    type=0 # all honeypot types
    numHoneypotDaemons = 0
    numHoneypotDaemonsOld = 0
    numHoneypots = 0
    numHoneypotsOld = 0 # pre 17.10
    internalDocker = 0
    listoutput=""

    if clientDomain:
        try:
            # find all 17.10 T-Pots
            res = es.search(index=esindex, body="""{
              "query": {
                "bool": {
                  "must": [
                    {
                      "term": {
                        "clientDomain": %s
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
                        "gte": "%s",
                        "lte": "%s"
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
                    "size": 100000
                  },
                    "aggs": {
                        "peerIdents": {
                            "terms": {
                                "field": "peerIdent.keyword"
                            }
                       }
                    }
                }
              }
            }""" %(str(clientDomain).lower(), utcTimeFrom, utcTimeTo))
            for i in range(len(res['aggregations']['hostnames']['buckets'])):
                for j in res['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets']:
                    listoutput+=("[" + res['aggregations']['hostnames']['buckets'][i]['key'] + "]" + "[" + j['key'] + "] : " + str(j['doc_count'])+ "\n")
                numHoneypotDaemons+=len(res['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets'])

            numHoneypots=len(res['aggregations']['hostnames']['buckets'])

            # Find older Honeypots via dest_ip
            res2 = es.search(index=esindex, body="""{
                "query": {
                    "bool": {
                        "must": [
                            {
                                "term": {
                                    "clientDomain": %s
                                }
                            },
                            {
                                "exists": {
                                    "field": "hostname.keyword"
                                }
                            },
                            {
                                "term": {
                                    "hostname.keyword": "undefined"
                                }
                            }
                        ],
                        "must_not": [
                            {
                                "term": {
                                    "hostname.keyword": ""
                                }
                            }
                        ],
                        "filter": {
                            "range": {
                                "recievedTime": {
                                    "gte": "%s",
                                    "lte": "%s"
                                }
                            }
                        }
                    }
                },
                "size": 0,
                "aggs": {
                    "hostnames": {
                        "terms": {
                            "field": "targetEntryIp",
                            "size": 100000
                        },
                        "aggs": {
                            "peerIdents": {
                                "terms": {
                                    "field": "peerIdent.keyword"
                                }
                            }
                        }
                    }
                }
            }""" % (str(clientDomain).lower(), utcTimeFrom, utcTimeTo))
            for i in range(len(res2['aggregations']['hostnames']['buckets'])):
                for j in res2['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets']:
                    listoutput+=("[" + res2['aggregations']['hostnames']['buckets'][i]['key'] + "]" + "[" + j['key'] + "] : " + str(j['doc_count']) + "\n")

                if ipaddress.ip_address(res2['aggregations']['hostnames']['buckets'][i]['key']) in ipaddress.ip_network('172.16.0.0/12'):
                    internalDocker+=len(res2['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets'])
                    numHoneypotDaemonsOld+=len(res2['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets'])
                else:
                    numHoneypotDaemonsOld+=len(res2['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets'])

            numHoneypotsOld=len(res2['aggregations']['hostnames']['buckets'])

            return numHoneypots+numHoneypotsOld, numHoneypotDaemons+numHoneypotDaemonsOld, res['hits']['total']+res2['hits']['total']

        except ElasticsearchException as err:
            app.logger.error('ElasticSearch error: %s' % err)
    else:
        try:
            res = es.search(index=esindex, body="""{
                  "query": {
                    "range": {
                      "recievedTime": {
                        "gte": "%s",
                        "lte": "%s"
                      }
                    }
                  },
                  "aggs": {
                    "communityfilter": {
                      "filter": {
                        "term": {
                          "clientDomain": %s
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
                }""" % (str(clientDomain).lower(), utcTimeFrom, utcTimeTo))


            return len(res['aggregations']['communityfilter']['hostnames']['buckets']),len(res['aggregations']['communityfilter']['hostnames']['buckets']),res['aggregations']['communityfilter']['doc_count']
        except ElasticsearchException as err:
            app.logger.error('ElasticSearch error: %s' % err)
    return False

def getNumberHoneypotTypes(app, clientDomain, es, esindex, utcTimeFrom, utcTimeTo):
    ''' retrieves destinct number of honeypots from index'''
    type=0 # all honeypot types
    numHoneypotDaemons = 0
    numHoneypotDaemonsOld = 0
    numHoneypots = 0
    numHoneypotsOld = 0 # pre 17.10
    internalDocker = 0
    listoutput=""
    daemonCount = dict()

    if clientDomain:
        try:
            # find all 17.10 T-Pots
            res = es.search(index=esindex, body="""{
              "query": {
                "bool": {
                  "must": [
                    {
                      "term": {
                        "clientDomain": %s
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
                                    "gte": "%s",
                                    "lte": "%s"
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
                    "size": 100000
                  },
                    "aggs": {
                        "peerTypes": {
                            "terms": {
                                "field": "peerType.keyword",
                                "size": 100000
                            }
                       }
                    }
                }
              }
            }""" % (str(clientDomain).lower(), utcTimeFrom, utcTimeTo))


            for peerIdent in res['aggregations']['hostnames']['buckets']:
                for peerType in peerIdent['peerTypes']['buckets']:
                    if peerType['key'] in daemonCount:
                        daemonCount[peerType['key']]+=1
                    else:
                        daemonCount[peerType['key']]=1


            # Find older Honeypots via dest_ip
            res2 = es.search(index=esindex, body="""{
                "query": {
                    "bool": {
                        "must": [
                            {
                                "term": {
                                    "clientDomain": %s
                                }
                            },
                            {
                                "exists": {
                                    "field": "hostname.keyword"
                                }
                            },
                            {
                                "term": {
                                    "hostname.keyword": "undefined"
                                }
                            }
                        ],
                        "must_not": [
                            {
                                "term": {
                                    "hostname.keyword": ""
                                }
                            }
                        ],
                        "filter": {
                            "range": {
                                "recievedTime": {
                                    "gte": "%s",
                                    "lte": "%s"
                                }
                            }
                        }
                    }
                },
                "size": 0,
                "aggs": {
                    "hostnames": {
                        "terms": {
                            "field": "targetEntryIp",
                            "size": 100000
                        },
                        "aggs": {
                            "peerTypes": {
                                "terms": {
                                    "field": "peerType.keyword",
                                    "size": 100000
                                }
                            }
                        }
                    }
                }
            }""" %(str(clientDomain).lower(), utcTimeFrom, utcTimeTo))

            for peerIdent in res2['aggregations']['hostnames']['buckets']:
                for peerType in peerIdent['peerTypes']['buckets']:
                    if peerType['key'] in daemonCount:
                        daemonCount[peerType['key']] += 1
                    else:
                        daemonCount[peerType['key']] = 1

            return daemonCount

        except ElasticsearchException as err:
            app.logger.error('ElasticSearch error: %s' % err)
    else:
        listoutput+="\n ------ detailed DTAG honeypot statistics ------\n\n"

        try:
            res = es.search(index=esindex, body="""{
              "query": {
                "bool": {
                  "must": [
                    {
                      "term": {
                        "clientDomain": %s
                      }
                    }
                  ],
                  "filter": {
                    "range": {
                      "recievedTime": {
                                    "gte": "%s",
                                    "lte": "%s"
                      }
                    }
                  }
                }
              },
              "size": 0,
              "aggs": {
                "peerIdent": {
                  "terms": {
                    "field": "peerIdent.keyword",
                    "size": 100000
                  },
                    "aggs": {
                        "peerTypes": {
                            "terms": {
                                "field": "peerType.keyword",
                                "size": 100000
                            }
                       }
                    }
                }
              }
            }""" %(str(clientDomain).lower(), utcTimeFrom, utcTimeTo))


            for peerIdent in res['aggregations']['peerIdent']['buckets']:
                for peerType in peerIdent['peerTypes']['buckets']:
                    if peerType['key'] in daemonCount:
                        daemonCount[peerType['key']] += 1
                    else:
                        daemonCount[peerType['key']] = 1

            return daemonCount

        except ElasticsearchException as err:
            app.logger.error('ElasticSearch error: %s' % err)
    return False




def getAlertsPerHoneypotType(app,clientDomain, es, esindex, utcTimeFrom,utcTimeTo):
    ''' retrieves number of alerts from index in timeframe (minutes)'''

    esquery="""
    {
          "query": {
            "bool": {
              "must": [
                {
                  "range": {
                    "recievedTime": {
                        "gte": "%s",
                        "lte": "%s"
                    }
                  }
                },
                {
                  "terms": {
                      "clientDomain":  [ %s ]
                    }
                }
              ]
            }
          },
          "aggs": {
            "peerType": {
              "terms": {
                "field": "peerType.keyword",
                "size": 1000
              }
            }
          },
          "size": 0
        }"""% (utcTimeFrom, utcTimeTo, str(clientDomain).lower())

    try:
        res = es.search(index=esindex, body=esquery)
        return res


    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' % err)

    return True


def getTPotAlertStatsJson(app, es, index, sdate):
    if sdate and sdate.isdecimal() and len(sdate) is 8:
        try:
            utcTimeFrom= datetime.datetime(int(sdate[0:4]),int(sdate[4:6]),int(sdate[6:8]))
        except:
            return False
    else:
        app.logger.error('getTPotAlertStatsJson: Provided incorrect date format: %s' % sdate)
        return False

    utcTimeTo=utcTimeFrom + datetime.timedelta(seconds=+86399)

    communityPeerStats=getAlertsPerHoneypotType(app, True, es, index, utcTimeFrom, utcTimeTo)
    communityInstallations = getNumberHoneypotsAndAlerts(app, True, es, index, utcTimeFrom, utcTimeTo)
    communityDaemons = getNumberHoneypotTypes(app, True ,es, index, utcTimeFrom, utcTimeTo)

    communityJson={}
    communityJson['totalNumberAlerts'] = communityPeerStats['hits']['total']
    communityJson['totalNumberHoneypots'] = communityInstallations[0]
    communityJson['totalNumberDaemons'] = communityInstallations[1]
    communityJson['numberAlertsPerType'] = dict()
    for peerType in communityPeerStats['aggregations']['peerType']['buckets']:
        communityJson['numberAlertsPerType'][peerType['key']] = peerType['doc_count']
    communityJson['numberHoneypotsPerType'] = dict()
    for peerType in communityDaemons:
        communityJson['numberHoneypotsPerType'][peerType] = communityDaemons.get(peerType)

    jsonResult = {}
    jsonResult['communityHoneypots'] = communityJson
    jsonResult['UTCtimeFrom'] = str(utcTimeFrom)
    jsonResult['UTCtimeTo'] = str(utcTimeTo)

    return jsonResult
