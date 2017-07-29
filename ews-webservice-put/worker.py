
import sys, getopt
import xml.etree.ElementTree as xmlParser
import elastic
from bottle import request, response, install, run, post, get, HTTPResponse
from datetime import datetime
from pymongo import MongoClient, errors
import hashlib



#
# default values
#

localServer = "localhost"
esindex = "ews3"
localPort = "8080"
elasticHost = "http://localhost:9200/"
useGUnicon = False
mongohost = "localhost"
mongoport = "27017"

#
# default credentials for community
#

username = "community-01-user"
password = "foth{a5maiCee8fineu7"


#
# Function area
#


# Authenticate user in mongodb
def authenticate(username, token):
    client = MongoClient(mongohost,  mongoport)
    db = client.ews
    try:
        dbresult = db.WSUser.find_one({'peerName': username})
        if dbresult == None:
            return False
        else:
            tokenhash = hashlib.sha512(token)
            if dbresult['token'] == tokenhash.hexdigest():
                    return True
            else:
                return False
    except errors.ServerSelectionTimeoutError as err:
        print('MongoDB cannot be reached: %s' %  err)
        return False



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
# Extract username and password from request
#
def extractAuth(tree):

    usernameFromRequest = ""
    passwordFromRequest = ""

    for node in tree.findall('.//Authentication'):

        for child in node:

            childName = child.tag

            if (childName == "token"):
                passwordFromRequest = child.text

            if (childName == "username"):
                    usernameFromRequest = child.text

    return usernameFromRequest, passwordFromRequest


#
# Check if community login
#
def handleCommunityAuth(usernameFromRequest, passwordFromRequest):

    return (username == usernameFromRequest) and (password == passwordFromRequest)

def checkPrivateIP(ip):
    return 0


def handleAlerts(tree, tenant):

    counter = 0

    for node in tree.findall('.//Alert'):

        # now parse the node

        source = ""
        destination = ""
        createTime = ""
        url = ""
        analyzerID = ""
        peerType = ""

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

    userNameFromRequest, passwordFromRequest = extractAuth(tree)

    if (handleCommunityAuth(userNameFromRequest, passwordFromRequest)):
        message = "<Result><StatusCode>OK</StatusCode><Text></Text></Result>"

        handleAlerts(tree, "c")
    else:
        print("Authentication failed....")

    response = {}
    headers = {'Content-type': 'application/html'}
    response['status'] = "Success"
    raise HTTPResponse(message, status=200, headers=headers)


#
# Read command line args
#
myopts, args = getopt.getopt(sys.argv[1:],"b:s:i:p:g:mh:mp")

for o, a in myopts:
    if o == '-s':
        elasticHost=a
    elif o == '-i':
        esindex=a
    elif o == '-p':
        localPort = a
    elif o == '-b':
        localServer=a
    elif o == '-g':
        useGUnicon = True
    elif o == '-mh':
        mongohost=a
    elif o == '-mp':
        mongoport=a
#
# start server depending on parameters given from shell or config file
#

print ("Starting DTAG early warning system input handler on server " + str(localServer) + ":" + str(localPort) + " with elasticsearch host at " + str(elasticHost) + " and index " + str(esindex) + " using mongo at " + str(mongohost)+ ":" + str(mongoport))

if (useGUnicon):
    run(host=localServer, port=localPort, server='gunicorn', workers=4)
else:
    run(host=localServer, port=localPort, catchall=True)
