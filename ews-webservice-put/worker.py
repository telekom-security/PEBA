
import sys, getopt
import xml.etree.ElementTree as xmlParser
import elastic
from bottle import request, response, install, run, post, get, HTTPResponse
from datetime import datetime


#
# default values
#

localServer = "localhost"
index = "ews3"
localPort = "10000"
elasticHost = "http://localhost:9200/"

#
# default credentials for community
#

username = "community-01-user"
password = "foth{a5maiCee8fineu7"


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



def handleAlerts(tree):

    counter = 0

    for node in tree.findall('.//Alert'):

        # now parse the node

        source = ""
        destination = ""
        createTime = ""

        for child in node:

            childName = child.tag

            if (childName == "Source"):
                source = child.text
            if (childName == "CreateTime"):
                createTime = child.text
            if (childName == "Target"):
                destination = child.text

        elastic.putAlarm(elasticHost, index, source, destination, createTime)
        counter = counter + 1


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

        handleAlerts(tree)
    else:
        print("Authentication failed....")

    response = {}
    headers = {'Content-type': 'application/html'}
    response['status'] = "Success"
    raise HTTPResponse(message, status=200, headers=headers)


#
# Read command line args
#
myopts, args = getopt.getopt(sys.argv[1:],"b:s:i:p:")

for o, a in myopts:
    if o == '-s':
        elasticHost=a
    elif o == '-i':
        index=a
    elif o == '-p':
        localPort = a
    elif o == '-b':
        localServer=a
    else:
        print("Usage: %s -b ip for the server -i index -s server -p port" % sys.argv[0])



run(host=localServer, port=localPort, catchall=True)
