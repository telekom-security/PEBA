import xml.etree.ElementTree as ET
import defusedxml.ElementTree as ETdefused
from flask import Flask, request, abort, jsonify, Response
from flask import current_app as app
from flask_cors import CORS, cross_origin
from flask_elasticsearch import FlaskElasticsearch
import urllib.request, urllib.parse, urllib.error
import elastic, communication
import ipaddress

################
# PUT Variables
################


peerIdents = ["WebHoneypot", "Webpage",
              "dionaea", "Network(Dionaea)",
              "honeytrap", "Network(honeytrap)",
              "kippo", "SSH/console(cowrie)",
              "cowrie", "SSH/console(cowrie)",
              "glastopf", "Webpage",
              ".gt3",  "Webpage",
              ".dio", "Network",
              ".kip", "SSH/console",
              "", ""]

################
# PUT functions
################



def checkPostData(postrequest):
    """check if postdata is XML"""
    postdata = postrequest.decode('utf-8')
    try:
        return ETdefused.fromstring(postdata)
    except ETdefused.ParseError:
        app.logger.error('Invalid XML in post request')
        return False

def getPeerType(id):
    """
        get the peerType from peerIdent
    """
    for i in range (0,len(peerIdents) - 2, 2):
         honeypot = peerIdents[i]
         peerType = peerIdents[i+1]

         if (honeypot in id):
             return peerType

    return "Unclassified"

def fixUrl(destinationPort, url, peerType):
    """
        fixes the URL (original request string)
    """
    if ("honeytrap" in peerType):
        return "Attack on port " + str(destinationPort)

    return url

def handleAlerts(tree, tenant, es, cache):
    """
        parse the xml, handle the Alerts and send to es
    """
    counter = 0
    for node in tree.findall('.//Alert'):
        # default values
        parsingError = ""
        skip = False
        peerType, vulnid, source, sourcePort, destination, destinationPort, createTime, url, analyzerID, username, password, loginStatus, version, starttime, endtime = "Unclassified", "", "","", "", "", "-", "", "", "", "", "", "", "", ""
        for child in node:
            childName = child.tag

            if (childName == "Analyzer"):
                if child.attrib.get('id') is not "":
                    analyzerID = child.attrib.get('id')
                else:
                    parsingError += "analyzerID = '' "
                if analyzerID is not "":
                    peerType = getPeerType(analyzerID)

            if (childName == "Source"):
                if child.text is not None and testIPAddress(child.text):
                    source = child.text.replace('"', '')
                else:
                    parsingError += "| source = NONE "
                sourcePort = child.attrib.get('port')

            if (childName == "CreateTime"):
                if child.text is not None:
                    createTime = child.text
                else:
                    parsingError += "| CreateTime = NONE "

            if (childName == "Target"):
                if child.text is not None and testIPAddress(child.text) :
                    destination = child.text.replace('"', '')
                else:
                    parsingError += "| destination = NONE "
                destinationPort = child.attrib.get('port')

            if (childName == "Request"):
                type = child.attrib.get('type')

                if (type == "url"):
                    if child.text is not None:
                        url = urllib.parse.unquote(child.text)
                    else:
                        parsingError += "| url = NONE "

                # if peertype could not be identified by the identifier of the honeypot, try to use the
                # description field
                if (type == "description" and peerType == ""):
                    peerType = getPeerType(child.text)

            if (childName == "AdditionalData"):
                meaning = child.attrib.get('meaning')

                if (meaning == "username"):
                    username = child.text

                if (meaning == "password"):
                    password = child.text

                if (meaning == "login"):
                    loginStatus = child.text

                if (meaning == "version"):
                    version = child.text

                if (meaning == "starttime"):
                    if child.text is not None:
                        starttime = urllib.parse.unquote(child.text)
                    else:
                        parsingError += "| starttime = NONE "

                if (meaning == "endtime"):
                    if child.text is not None:
                        endtime = urllib.parse.unquote(child.text)
                    else:
                        parsingError += "| endtime = NONE "

                if (meaning == "cve_id"):
                    if child.text is not None:
                        vulnid = urllib.parse.unquote(child.text)
                    else:
                        parsingError += "| cve_id = NONE "

                if (meaning == "input"):
                    if child.text is not None:
                        url = urllib.parse.unquote(child.text).replace('\n', '; ')[2:]
                    else:
                        parsingError += "| input = NONE "

        if parsingError is not "":
            app.logger.debug("Skipping incomplete ews xml alert element : " + parsingError)
            skip = True

        if not skip:
            url = fixUrl(destinationPort, url, peerType)

            #
            # persist CVE
            #
            if (len(str(vulnid)) > 2):
                elastic.putVuln(vulnid, app.config['ELASTICINDEX'], createTime, source, app.config['DEVMODE'], es )
                url = "(" + vulnid + ") " + url

            #
            # store attack itself
            #
            correction = elastic.putAlarm(vulnid, app.config['ELASTICINDEX'], source, destination, createTime, tenant, url,
                                          analyzerID, peerType, username, password, loginStatus, version, starttime,
                                          endtime, sourcePort, destinationPort, app.config['DEVMODE'], es, cache)
            counter = counter + 1 - correction

            #
            # slack wanted
            #
            if (app.config['USESLACK']):
                if len(str(app.config['SLACKTOKEN'])) > 10:
                    if len(str(vulnid)) > 4:
                        if (elastic.cveExisting(vulnid, app.config['ELASTICINDEX'], es, app.config['DEVMODE'])):
                            communication.sendSlack("cve", app.config['SLACKTOKEN'], "CVE (" + vulnid + ") found.", app.config['DEVMODE'])

    app.logger.debug("Info: Added " + str(counter) + " entries")
    return True

def testIPAddress(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except:
        return False
