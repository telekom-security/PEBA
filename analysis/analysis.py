#!/usr/bin/env python
# -*- coding: utf-8 -*-

# script to gather analysis data from es index
# v0.1

import datetime, sys
from elasticsearch import Elasticsearch, ElasticsearchException
import ipaddress
import argparse
import json
import time




########################
### INIT
#######################

esindex="ews-*"

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
        # stub for connection test data store
        return True
    except:
        return False

def handleHoneypotAlerts(timeframe,clientDomain):
    ''' retrieves and stores information over timeframe in minutes and cindex'''
    res=getNumberHoneypotsAndAlerts(timeframe, clientDomain, 0)
    setAlertsOverTime(timeframe,
                      res[0],
                      res[1],
                      res[2],
                      clientDomain)
    return True

########################
### Functions to GET data
########################

def getNumberHoneypotsAndAlerts(timeframe, clientDomain, type):
    ''' retrieves destinct number of honeypots from index'''
    type=0 # all honeypot types
    numHoneypotDaemons = 0
    numHoneypotDaemonsOld = 0
    numHoneypots = 0
    numHoneypotsOld = 0 # pre 17.10
    internalDocker = 0
    listoutput=""

    if clientDomain:
        listoutput+="\n ------ detailed community honeypot statistics ------\n\n"
        try:
            # find all 17.10 T-Pots
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
            })
            for i in range(len(res['aggregations']['hostnames']['buckets'])):
                #print(res['aggregations']['hostnames']['buckets'][i]['key'] + str(res['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets']))
                for j in res['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets']:
                    listoutput+=("[" + res['aggregations']['hostnames']['buckets'][i]['key'] + "]" + "[" + j['key'] + "] : " + str(j['doc_count'])+ "\n")
                numHoneypotDaemons+=len(res['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets'])

            numHoneypots=len(res['aggregations']['hostnames']['buckets'])
            if args.verbose:
                print("COMMUNITY >= 17.10 --> " + str(numHoneypots) + " T-Pot installations with a total of " + str(numHoneypotDaemons) + " honeypot daemons, accounting for " +str(res['hits']['total'])+ " alerts.")


            # Find older Honeypots via dest_ip
            res2 = es.search(index=esindex, body={
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
            })

            for i in range(len(res2['aggregations']['hostnames']['buckets'])):
                for j in res2['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets']:
                    listoutput+=("[" + res2['aggregations']['hostnames']['buckets'][i]['key'] + "]" + "[" + j['key'] + "] : " + str(j['doc_count']) + "\n")

                if ipaddress.ip_address(res2['aggregations']['hostnames']['buckets'][i]['key']) in ipaddress.ip_network('172.16.0.0/12'):
                    #print("interne docker ip addresse : " + res2['aggregations']['hostnames']['buckets'][i]['key']+ " ---> " + str(res2['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets']))
                    internalDocker+=len(res2['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets'])
                    numHoneypotDaemonsOld+=len(res2['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets'])
                else:
                    #print(res2['aggregations']['hostnames']['buckets'][i]['key'] + " ---> " + str(res2['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets']))
                    numHoneypotDaemonsOld+=len(res2['aggregations']['hostnames']['buckets'][i]['peerIdents']['buckets'])

            numHoneypotsOld=len(res2['aggregations']['hostnames']['buckets'])
            if args.verbose:
                print("COMMUNITY < 17.10 --> " + str(numHoneypotsOld) + " T-Pot installations with a total of " + str(numHoneypotDaemonsOld) + " honeypot daemons, accounting for " + str(res2['hits']['total'])+ " alerts -  including " + str(internalDocker) + " hosts with internal docker ip (might be counted only once)")

            # total sum
            if args.verbose:
                    print("COMMUNITY TOTAL : " + str(numHoneypots+numHoneypotsOld) + " T-Pot installations, with a total of " + str(numHoneypotDaemons+numHoneypotDaemonsOld) + " honeypot daemons, accounting for " + str(res['hits']['total']+res2['hits']['total']) + " alerts." )

            if args.verbose:
                print(listoutput)


            return numHoneypots+numHoneypotsOld, numHoneypotDaemons+numHoneypotDaemonsOld, res['hits']['total']+res2['hits']['total']


        except ElasticsearchException as err:
            print('ElasticSearch error: %s' % err)
    else:
        listoutput+="\n ------ detailed DTAG honeypot statistics ------\n\n"

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

            if args.verbose:
                print("DTAG TOTAL --> " + str(len(res['aggregations']['communityfilter']['hostnames']['buckets'])) + " honeypot daemons, accounting for " +  str(res['aggregations']['communityfilter']['doc_count']) + " alerts.")

            for i in res['aggregations']['communityfilter']['hostnames']['buckets']:
                listoutput+="[DTAG][" + i['key'] + "] : " + str(i['doc_count']) + "\n"

            if args.verbose:
                print(listoutput)

            return len(res['aggregations']['communityfilter']['hostnames']['buckets']),len(res['aggregations']['communityfilter']['hostnames']['buckets']),res['aggregations']['communityfilter']['doc_count']
        except ElasticsearchException as err:
            print('ElasticSearch error: %s' % err)
    return False

def getNumberHoneypotTypes(timeframe, clientDomain, type):
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
            })


            for peerIdent in res['aggregations']['hostnames']['buckets']:
                for peerType in peerIdent['peerTypes']['buckets']:
                    if peerType['key'] in daemonCount:
                        daemonCount[peerType['key']]+=1
                    else:
                        daemonCount[peerType['key']]=1


            # Find older Honeypots via dest_ip
            res2 = es.search(index=esindex, body={
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
            })

            for peerIdent in res2['aggregations']['hostnames']['buckets']:
                for peerType in peerIdent['peerTypes']['buckets']:
                    if peerType['key'] in daemonCount:
                        daemonCount[peerType['key']] += 1
                    else:
                        daemonCount[peerType['key']] = 1

            return daemonCount

        except ElasticsearchException as err:
            print('ElasticSearch error: %s' % err)
    else:
        listoutput+="\n ------ detailed DTAG honeypot statistics ------\n\n"

        try:
            res = es.search(index=esindex, body={
              "query": {
                "bool": {
                  "must": [
                    {
                      "term": {
                        "clientDomain": clientDomain
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
            })


            for peerIdent in res['aggregations']['peerIdent']['buckets']:
                for peerType in peerIdent['peerTypes']['buckets']:
                    if peerType['key'] in daemonCount:
                        daemonCount[peerType['key']] += 1
                    else:
                        daemonCount[peerType['key']] = 1

            return daemonCount

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

def getAlertsPerHoneypotType(timeframe, clientDomain):
    ''' retrieves number of alerts from index in timeframe (minutes)'''

    esquery="""
    {
          "query": {
            "bool": {
              "must": [
                {
                  "range": {
                    "recievedTime": {
                        "gte": "now-%sm" 
                    }
                  }
                },
                {
                  "terms": {
                      "clientDomain": [ %s ]
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
        }"""% (timeframe, str(clientDomain).lower())

    try:
        res = es.search(index=esindex, body=esquery)
        return res


    except ElasticsearchException as err:
        print('ElasticSearch error: %s' % err)

    return True


def getAlertStatsJson():
    communityPeerStats=getAlertsPerHoneypotType(args.minutes, True)
    peerStats=getAlertsPerHoneypotType(args.minutes, False)
    communityInstallations = getNumberHoneypotsAndAlerts(args.minutes, True, 0)
    peerInstallations = getNumberHoneypotsAndAlerts(args.minutes, False, 0)
    communityDaemons = getNumberHoneypotTypes(args.minutes, True,0)
    peerDaemons = getNumberHoneypotTypes(args.minutes, False,0)

    timeNow = datetime.datetime.utcnow()
    timeFrom = timeNow + datetime.timedelta(0, -args.minutes * 60)

    privateJson={}
    privateJson['totalNumberAlerts'] = peerStats['hits']['total']
    privateJson['totalNumberHoneypots'] = peerInstallations[0]
    privateJson['totalNumberDaemons'] = peerInstallations[1]
    privateJson['numberAlertsPerType'] = dict()
    for peerType in peerStats['aggregations']['peerType']['buckets']:
        privateJson['numberAlertsPerType'][peerType['key']] = peerType['doc_count']
    privateJson['numberHoneypotsPerType'] = dict()
    for peerType in peerDaemons:
        privateJson['numberHoneypotsPerType'][peerType] = peerDaemons.get(peerType)

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
    jsonResult['privateHoneypots'] = privateJson
    jsonResult['communityHoneypots'] = communityJson
    jsonResult['UTCtimeFrom'] = str(timeFrom)
    jsonResult['UTCtimeTo'] = str(timeNow)


    print(json.dumps(jsonResult, indent=4, sort_keys=True))
    with open("./stats.json", "w") as fh:
        fh.write(json.dumps(jsonResult, indent=4, sort_keys=True))


########################
### Functions to SET data
########################

def setAlertsOverTime(timeframe, numberTpots, numberHoneypots, numberAlerts, cindex):
    timestamp=datetime.datetime.now().time()
    span=timeframe
    alert_count=numberAlerts
    honeypot_count=numberHoneypots
    tpot_count=numberTpots
    domain=cindex
    #print("timeframe: " + str(span) + "min | number of alerts: " +  str(alert_count)+ " | determined number of T-Pot installations: " + str(tpot_count) + " | number of honeypot daemons: " + str(honeypot_count) + " | community: " + str(cindex))

    # TODO: Store data in DB

    return True



########################
### Start getting data
#######################

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='PEBA Honeypot Statistics.')
    parser.add_argument('minutes', default=5, nargs='?', type=int, help='number of minutes to consider, default: 5')
    parser.add_argument('-v',"--verbose",action='store_true',help='verbose: output detailed numbers per honeypot daemon')
    args=parser.parse_args()

    if not testElasticsearch():
        print("ELASTIC SEARCH UNREACHABLE. EXITING")
        exit(1)
    if not testDataStore():
        print("DATASTORE UNREACHABLE. EXITING")
        exit(1)

    #### Retrieve Data

    print("Retrieving statistics for the last " + str(args.minutes)+ " minute(s):")

    # generate statistical data
    getAlertStatsJson()
