
import xml.etree.ElementTree as xmlParser
import elastic, auth, sys, getopt, config
from bottle import request, response, install, run, post, get, HTTPResponse
from datetime import datetime

localServer, esindex, localPort, elasticHost, mongohost, mongoport = "", "", "", "", "", ""

createIndex = False
useConfigFile = True

#
# Function area
#

def logger(func):
    def wrapper(*args, **kwargs):
        log = open('/var/log/ewsput.txt', 'a')
        log.write('%s %s %s %s %s \n' % (request.remote_addr, datetime.now().strftime('%H:%M'),
                                         request.method, request.url, response.status))
        log.close()
        req = func(*args, **kwargs)
        return req
    return wrapper

install(logger)



#
#
#
def handleAlerts(tree, tenant):

    counter = 0

    for node in tree.findall('.//Alert'):

        # now parse the node

        source, destination, createTime, url, analyzerID, peerType = "", "", "", "", "", ""

        for child in node:

            childName = child.tag

            if (childName == "Source"):
                source = child.text
            if (childName == "CreateTime"):
                createTime = child.text
            if (childName == "Target"):
                destination = child.text

            if (childName == "Request"):
                type = child.attrib.get('type')

                if (type == "url"):
                    url = child.text

            if (childName == "Analyzer"):
                analyzerID = child.attrib.get('id')

        correction = elastic.putAlarm(elasticHost, esindex, source, destination, createTime, tenant, url, analyzerID, peerType)
        counter = counter + 1 - correction


    print ("Info: Added " + str(counter) + " entries")
    return True



@get('/')
def index():
    message = ""
    response = {}
    headers = {'Content-type': 'application/html'}
    response['status'] = "Success"
    raise HTTPResponse(message, status=200, headers=headers)


@post('/ews-0.1/alert/postSimpleMessage')
def postSimpleMessage():

    postdata = request.body.read().decode("utf-8")

    message = "<Result><StatusCode>FAILED</StatusCode><Text>Authentication failed.</Text></Result>"

    tree = xmlParser.fromstring(postdata)

    userNameFromRequest, passwordFromRequest = auth.extractAuth(tree)

    if (auth.handleCommunityAuth(userNameFromRequest, passwordFromRequest)):

        message = "<Result><StatusCode>OK</StatusCode><Text></Text></Result>"
        handleAlerts(tree, True)

    elif auth.authenticate(userNameFromRequest, passwordFromRequest, mongohost, mongoport):

        message = "<Result><StatusCode>OK</StatusCode><Text></Text></Result>"
        handleAlerts(tree, False)
    else:
        print("Authentication failed....")

    response = {}
    headers = {'Content-type': 'application/html'}
    response['status'] = "Success"
    raise HTTPResponse(message, status=200, headers=headers)


(elasticHost, esindex, localServer, localPort, mongoport, mongohost,  createIndex, useConfigFile) = config.readCommandLine(elasticHost, esindex, localServer, localPort, mongoport, mongohost, createIndex, useConfigFile)

if (createIndex):
    print ("Info: Just creating an index " + esindex)
    elastic.initIndex(elasticHost, esindex)

else:

    if (useConfigFile):
        print ("Info: Using configfile")
        (elasticHost, esindex, localServer, localPort, mongoport, mongohost, createIndex) = config.readconfig(elasticHost, esindex, localServer, localPort, mongoport, mongohost)

    #
    # start server depending on parameters given from shell or config file
    #

    print ("Starting DTAG early warning system input handler on server " + str(localServer) + ":" + str(localPort) + " with elasticsearch host at " + str(elasticHost) + " and index " + str(esindex) + " using mongo at " + str(mongohost)+ ":" + str(mongoport))

    run(host=localServer, port=localPort, server='gunicorn', workers=4)

