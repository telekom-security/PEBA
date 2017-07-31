from configparser import ConfigParser
import sys, getopt



def readconfig(elasticHost, esindex, localServer, localPort, mongoport, mongohost):
    config = ConfigParser()

    candidates = ['/etc/ews/ewsput.cfg', './ewsput.cfg']

    config.read(candidates)

    elasticHost = config.get("elasticsearch", "ip")
    esindex = config.get("elasticsearch", "index")

    localServer = config.get('home', 'ip')
    localPort = config.get('home', 'port')

    mongohost = config.get('mongo', 'ip')
    mongoport = config.get('mongo', 'port')

    return (elasticHost, esindex, localServer, localPort, mongoport, mongohost, False)


def readCommandLine(elasticHost, esindex, localServer, localPort, mongoport, mongohost, createIndex, useConfigFile):

    #
    # Read command line args
    #
    myopts, args = getopt.getopt(sys.argv[1:], "b:s:i:p:mh:mp:c")

    for o, a in myopts:
        useConfigFile = False

        if o == '-s':
            elasticHost = a
        elif o == '-i':
            esindex = a
        elif o == '-p':
            localPort = a
        elif o == '-b':
            localServer = a
        elif o == '-mh':
            mongohost = a
        elif o == '-mp':
            mongoport = a
        elif o == '-c':
            createIndex = True

    return (elasticHost, esindex, localServer, localPort, mongoport, mongohost, createIndex, useConfigFile)
