#!/usr/bin/env python
# -*- coding: utf-8 -*-

# module to gather t-pot installation data
# v0.1

import datetime
from elasticsearch import Elasticsearch, ElasticsearchException
import ipaddress
from collections import OrderedDict
import json

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
                        "field": "hostname"
                      }
                    }
                  ],
                  "must_not": [
                    {
                      "term": {
                        "hostname": "undefined"
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
                    "field": "hostname",
                    "size": 100000
                  },
                    "aggs": {
                        "peerIdents": {
                            "terms": {
                                "field": "peerIdent"
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
                                    "field": "hostname"
                                }
                            },
                            {
                                "term": {
                                    "hostname": "undefined"
                                }
                            }
                        ],
                        "must_not": [
                            {
                                "term": {
                                    "hostname": ""
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
                                    "field": "peerIdent"
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
                            "field": "peerIdent",
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
                        "field": "hostname"
                      }
                    }
                  ],
                  "must_not": [
                    {
                      "term": {
                        "hostname": "undefined"
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
                    "field": "hostname",
                    "size": 100000
                  },
                    "aggs": {
                        "peerTypes": {
                            "terms": {
                                "field": "peerType",
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
                                    "field": "hostname"
                                }
                            },
                            {
                                "term": {
                                    "hostname": "undefined"
                                }
                            }
                        ],
                        "must_not": [
                            {
                                "term": {
                                    "hostname": ""
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
                                    "field": "peerType",
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
                    "field": "peerIdent",
                    "size": 100000
                  },
                    "aggs": {
                        "peerTypes": {
                            "terms": {
                                "field": "peerType",
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
                "field": "peerType",
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

def getStats(app, es, statisticIndex, gte ,lt, queryValue):
    ''' retrieves statistics from es statistics index in timeframe (minutes)'''

    # HP Statistics per Type
    HPItems = [ 'E-Mail(mailoney)',
                'Industrial(conpot)',
                'Network(cisco-asa)',
                'Network(Dionaea)',
                'Network(glutton)',
                'Network(honeytrap)',
                'Network(suricata)',
                'Passwords(heralding)',
                'RDP(rdpy)',
                'SSH/console(cowrie)',
                'Service(ES)',
                'Service(emobility)',
                'Service(Medicine)',
                'VNC(vnclowpot)',
                'Webpage',
                'Unclassified'
                ]


    queryValues = ['UTCtimeFrom',
                   'UTCtimeTo',
    #               'comm_totalNumberAlerts',
    #               'comm_totalNumberHoneypots',
    #               'comm_totalNumberDaemons',
                   'comm_totalRatio'
                   ]

    for i in queryValue:
        if i in HPItems:
     #       queryValues.append('comm_totalAlerts_'+i)
     #       queryValues.append('comm_totalHPs_'+i)
            queryValues.append('comm_ratio_'+i)
        else:
            app.logger.error("getStats: unrecognized honeypot value: %s" % i)
    queryString='"'
    queryString+='","'.join(queryValues)+'"'

    app.logger.debug("getStats: setting gte to : " + gte)
    app.logger.debug("getStats: setting lt to: " + lt)
    app.logger.debug("getStats: querying statistic data for %s" %queryString)

    esquery="""
        {
          "query": {
            "bool": {
              "must": [
                {
                  "range": {
                    "UTCtimeFrom": {
                      "gte": "%s",
                      "lte": "%s"
                    }
                  }
                }
              ],
              "must_not": [],
              "should": []
            }
          },
          "from": 0,
          "size": 5000,
          "sort": {
                "UTCtimeFrom": {
                    "order": "asc"
                    }
                },
          "aggs": {},
          "_source": [
                %s
                ]
            }
        }
    """ % (gte, lt, queryString)

    try:
        res = es.search(index=statisticIndex, body=esquery)

    except ElasticsearchException as err:
        app.logger.error('ElasticSearch error: %s' % err)
        return False

    result = OrderedDict()
    for days in res['hits']['hits']:
        datefrom=days['_source']['UTCtimeFrom']
        res2 = OrderedDict()
        for stats in days['_source']:
            res2[stats] = days['_source'][stats]
        result[datefrom] = res2

    return result

def getTops(app, es, esindex, days, toptype, topnumber):
    # get the top 10
    if toptype == "urls":

        if days > 1:
            if days == 7:
                resolution="6h"
            elif days == 28:
                resolution = "day"
            minday = "{:%Y-%m-%d}".format(datetime.datetime.utcnow() + datetime.timedelta(days=-(int(days)-1)))
            maxday = "{:%Y-%m-%d}".format(datetime.datetime.utcnow())
            esquery = """
                {
                  "query": {
                    "bool": {
                      "must": [
                       {
                        "range":{
                            "recievedTime":{
                                "gte":"%s"
                                }}
                                },
                        {
                        "term":{
                            "peerType":"Webpage"}}
                      ],
                      "must_not": [],
                      "should": []
                    }
                  },
                  "from": 0,
                  "size": 0,
                  "sort": [],
                  "aggs": {
                    "url": {
                      "terms": {
                        "field": "originalRequestString",
                        "size": %s
                      },
                  "aggs": {
                     "range": {
                          "date_histogram": {
                            "field": "recievedTime",
                            "interval": "%s",
                            "keyed": false,
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": "%s", 
                                "max": "%s"
                            }                            
                        }}}
                    }
                  }
                }
            """ % (minday, topnumber, resolution, minday, maxday)
        else:
            minday = "{:%Y-%m-%d %H:%M:%S}".format(datetime.datetime.utcnow() + datetime.timedelta(days=-days))
            maxday = "{:%Y-%m-%d %H:%M:%S}".format(datetime.datetime.utcnow())
            esquery = """
                {
                  "query": {
                    "bool": {
                      "must": [
                        {
                        "range":{
                            "recievedTime":{
                                "gte":"%s"
                                }}
                                },
                        {
                        "term":{
                            "peerType":"Webpage"}}
                      ],
                      "must_not": [],
                      "should": []
                    }
                  },
                  "from": 0,
                  "size": 0,
                  "sort": [],
                  "aggs": {
                    "url": {
                      "terms": {
                        "field": "originalRequestString",
                        "size": %s
                      },
                  "aggs": {
                     "range": {
                          "date_histogram": {
                            "field": "recievedTime",
                            "interval": "hour",
                            "keyed": false,
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": "%s", 
                                "max": "%s"
                            }                            
                        }}}
                    }
                  }
                }
            """ % (minday,topnumber, minday, maxday)

        try:
            res = es.search(index=esindex, body=esquery)
        except ElasticsearchException as err:
            app.logger.error('ElasticSearch error: %s' % err)
            return False

        stats = OrderedDict()
        for url in res['aggregations']['url']['buckets']:
            daystats = OrderedDict()
            daystats['total'] = url['doc_count']
            for day in url['range']['buckets']:
                daystats[day['key_as_string']] = day['doc_count']
            stats[url['key']] = daystats

        return(stats)

    if toptype == "destports":

        if days > 1:
            if days == 7:
                resolution="6h"
            elif days == 28:
                resolution = "day"
            minday = "{:%Y-%m-%d}".format(datetime.datetime.utcnow() + datetime.timedelta(days=-(int(days)-1)))
            maxday = "{:%Y-%m-%d}".format(datetime.datetime.utcnow())
            esquery = """
                {
                  "query": {
                    "bool": {
                      "must": [
                       {
                        "range":{
                            "recievedTime":{
                                "gte":"%s"
                                }}
                                }
                      ],
                      "must_not": [],
                      "should": []
                    }
                  },
                  "from": 0,
                  "size": 0,
                  "sort": [],
                  "aggs": {
                    "ports": {
                      "terms": {
                        "field": "targetEntryPort",
                        "size": %s
                      },
                  "aggs": {
                     "range": {
                          "date_histogram": {
                            "field": "recievedTime",
                            "interval": "%s",
                            "keyed": false,
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": "%s", 
                                "max": "%s"
                            }                            
                        }}}
                    }
                  }
                }
            """ % (minday, topnumber, resolution, minday, maxday)
        else:
            minday = "{:%Y-%m-%d %H:%M:%S}".format(datetime.datetime.utcnow() + datetime.timedelta(days=-days))
            maxday = "{:%Y-%m-%d %H:%M:%S}".format(datetime.datetime.utcnow())
            esquery = """
                {
                  "query": {
                    "bool": {
                      "must": [
                        {
                        "range":{
                            "recievedTime":{
                                "gte":"%s"
                                }}
                                }
                      ],
                      "must_not": [],
                      "should": []
                    }
                  },
                  "from": 0,
                  "size": 0,
                  "sort": [],
                  "aggs": {
                    "ports": {
                      "terms": {
                        "field": "targetEntryPort",
                        "size": %s
                      },
                  "aggs": {
                     "range": {
                          "date_histogram": {
                            "field": "recievedTime",
                            "interval": "hour",
                            "keyed": false,
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": "%s", 
                                "max": "%s"
                            }                            
                        }}}
                    }
                  }
                }
            """ % (minday,topnumber, minday, maxday)

        try:
            res = es.search(index=esindex, body=esquery)
        except ElasticsearchException as err:
            app.logger.error('ElasticSearch error: %s' % err)
            return False

        stats = OrderedDict()
        for port in res['aggregations']['ports']['buckets']:
            daystats = OrderedDict()
            daystats['total'] = port['doc_count']
            for day in port['range']['buckets']:
                daystats[day['key_as_string']] = day['doc_count']
            stats[port['key']] = daystats

        return (stats)