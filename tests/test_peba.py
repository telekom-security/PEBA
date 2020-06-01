import pytest
from peba import app
from es_fixtures import es_data
import datetime
import hashlib
import xml.etree.ElementTree as ET

# es connection information in misc/setupESindices.py
from misc.setupESindices import setup_UserIndex, setup_alertsIndex, es, index_alias_alert, index_name_users

fillupES=40


def authenticate():
    return '<EWS-SimpleMessage version="2.0"><Authentication><username>test</username><token>testpass</token></Authentication></EWS-SimpleMessage>'

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture(scope="session", autouse=True)
def setup_indices(request):
    # setup user and alert index in ES
    setup_UserIndex()
    setup_alertsIndex()

    # delete alert es content
    es.delete_by_query(index=index_alias_alert, body={"query": {"match_all": {}}})
    # delete user es content
    es.delete_by_query(index=index_name_users, body={"query": {"match_all": {}}})

    # add user test:testpass to users index
    testuser = {
        'peerName': 'test',
        'token': hashlib.sha512("testpass".encode('utf-8')).hexdigest(),
        'getOnly': False,
        'community': False,
        'email': 'test@test.de'
    }
    es.index(index=index_name_users, doc_type='wsUser', body=testuser)

    # add alerts
    x = datetime.datetime.now()
    for counter, i in enumerate(es_data):
        es_data[counter]['recievedTime'] = x.strftime('%Y-%m-%d %H:%M:%S')
        es_data[counter]['createTime'] = (x - datetime.timedelta(seconds=(counter + 10))).strftime('%Y-%m-%d %H:%M:%S')

    # add single alert with old create and received time
    e = es_data[-1].copy()
    e['recievedTime'] = (x - datetime.timedelta(hours=30)).strftime('%Y-%m-%d %H:%M:%S')
    e['createTime'] = (x - datetime.timedelta(hours=30)).strftime('%Y-%m-%d %H:%M:%S')
    es_data.append(e)

    # fill up alerts with fist alert entry
    for i in range(fillupES):
        es_data.append(es_data[0])

    # store in ES
    for i in es_data:
        es.index(index=index_alias_alert, doc_type="Alert", body=i, refresh=True)


def test_getRoot(client):
    response = client.get("/")
    assert response.status_code == 302
    assert response.headers.get("Location") == "https://sicherheitstacho.eu"


def test_getHeartbeat(client):
    response = client.get("/heartbeat")
    assert response.status_code == 200
    assert response.data == b"I'm alive"


def test_getRetrieveAlertsCount(client):
    response = client.get("/alert/retrieveAlertsCount?time=10")
    assert response.status_code == 200
    assert '<AlertCount>{}</AlertCount>'.format(len(es_data) - 1) in response.data.decode('utf-8')


def test_getRetrieveAlertsCount1800(client):
    response = client.get("/alert/retrieveAlertsCount?time=1800")
    assert response.status_code == 200
    assert '<AlertCount>{}</AlertCount>'.format(len(es_data)) in response.data.decode('utf-8')


def test_getRetrieveAlertsCountJson(client):
    response = client.get("/alert/retrieveAlertsCount?time=10&out=json")
    assert response.status_code == 200
    assert "AlertCount" in response.get_json()
    assert response.get_json()['AlertCount'] == len(es_data) - 1


def test_getRetrieveAlertsCount1800Json(client):
    response = client.get("/alert/retrieveAlertsCount?time=1800&out=json")
    assert response.status_code == 200
    assert "AlertCount" in response.get_json()
    assert response.get_json()['AlertCount'] == len(es_data)


def test_retrieveAlertsJson(client):
    response = client.get("/alert/retrieveAlertsJson?ci=-1")
    assert "alerts" in response.get_json()
    assert len(response.get_json()['alerts']) == 35
    for i in ['analyzerType', 'clientDomain', 'country', 'countryName', 'dateCreated', 'destLat', 'destLng', 'id',
              'requestString', 'sourceLat', 'sourceLng', 'targetCountry']:
        assert i in response.get_json()['alerts'][0]
    #assert es_data[0]['recievedTime'] == response.get_json()['alerts'][-1]['dateCreated']

def test_retrieveAlertStats(client):
    response = client.get("/alert/retrieveAlertStats?ci=-1")
    assert response.status_code == 200
    assert "AlertsLast24Hours" in response.get_json()
    assert "AlertsLast5Minutes" in response.get_json()
    assert "AlertsLastHour" in response.get_json()
    assert "AlertsLastMinute" in response.get_json()
    assert response.get_json()['AlertsLastMinute'] == len(es_data)-1

def test_retrieveAlertsCountWithType(client):
    response = client.get("/alert/retrieveAlertsCountWithType?time=1&ci=-1")
    assert response.status_code == 200
    assert "AlertCountPerType" in response.get_json()
    assert response.get_json()['AlertCountTotal'] == len(es_data)-1
    assert response.get_json()['AlertCountPerType']['Network(dionaea)'] == 1
    assert response.get_json()['AlertCountPerType']['Passwords(heralding)'] == len(es_data)-2

def test_topCountriesAttacks(client):
    response = client.get("/alert/topCountriesAttacks?ci=-1")
    assert response.status_code == 200
    assert "attacksPerCountry" in response.get_json()[0]
    assert "attacksToTargetCountry" in response.get_json()[0]
    assert response.get_json()[0]['attacksPerCountry'][0]['code'] == "PIR"
    assert response.get_json()[0]['attacksToTargetCountry'][0]['code'] == "DE"

def test_retrieveIPs(client):
    response = client.post("/alert/retrieveIPs?out=json&ci=-1", data=authenticate())
    assert response.status_code == 200
    # this endpoint only shows RFC1918 PUBLIC IPs
    assert len(response.get_json()) == 1
    assert response.get_json()[0]['ip'] == "87.150.238.111"
    assert response.get_json()[0]['count'] == (1+fillupES)

def test_retrieveIPs15m(client):
    response = client.post("/alert/retrieveIPs15m?ci=-1", data=authenticate())
    assert response.status_code == 200
    # this endpoint only shows RFC1918 PUBLIC IPs, only one dataset (x fillupES) has a public IP
    assert '<Address>{}</Address>'.format("87.150.238.111") in response.data.decode('utf-8')
    assert '<Count>{}</Count>'.format(1+fillupES) in response.data.decode('utf-8')

def test_retrieveAlertsCyber(client):
    response = client.post("/alert/retrieveAlertsCyber", data=authenticate())
    assert response.status_code == 200
    tree = ET.fromstring(response.data)
    assert len(tree[0]) == app.config['MAXALERTS']
    assert tree[0][0][0].tag == "Id"
    assert tree[0][1][2][1].tag == "Type"
    assert tree[0][2][4][1].tag == "Country"
    for i in tree[0]:
        assert "community-01" in i[2][0].text

def test_querySingleIP(client):
    response = client.post("/alert/querySingleIP?ip=87.150.238.111", data=authenticate())
    assert response.status_code == 200
    tree = ET.fromstring(response.data)
    assert len(tree[0]) == app.config['MAXALERTS']
    assert tree[0][0][1].tag == "DateCreated"
    assert tree[0][1][2][1].text == "DE"
    for i in tree[0]:
        assert i[2][0].text in ['Passwords(heralding)','Network(dionaea)']

def test_datasetAlertsPerMonth(client):
    response = client.get("/alert/datasetAlertsPerMonth?ci=-1&days=1")
    assert response.status_code == 200
    lastDay = list(response.get_json()[0]['datasetAlertsPerMonth'])[0]
    thisDay = list(response.get_json()[0]['datasetAlertsPerMonth'])[1]
    assert response.get_json()[0]['datasetAlertsPerMonth'][lastDay]  == 1
    assert response.get_json()[0]['datasetAlertsPerMonth'][thisDay] == len(es_data)-1

def test_topCountriesAttacks(client):
    response = client.get("/alert/topCountriesAttacks")
    assert response.status_code == 200
    assert response.get_json()[0]['attacksPerCountry'][0]['code'] == "PIR"
    assert response.get_json()[0]['attacksPerCountry'][0]['count'] == 1
    assert response.get_json()[0]['attacksToTargetCountry'][0]['code'] == "DE"
    assert response.get_json()[0]['attacksToTargetCountry'][0]['count'] == 1


def test_datasetAlertTypesPerMonth(client):
    response = client.get("/alert/datasetAlertTypesPerMonth?days=2")
    assert response.status_code == 200
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    yesterday = (datetime.datetime.now()-datetime.timedelta(hours=(24))).strftime('%Y-%m-%d')
    assert response.get_json()[0]['datasetAlertsPerMonth'][yesterday+" 00:00:00"]['Passwords(heralding)'] == 1
    assert response.get_json()[0]['datasetAlertsPerMonth'][today+" 00:00:00"]['Network(dionaea)'] == 1
    assert response.get_json()[0]['datasetAlertsPerMonth'][today+" 00:00:00"]['Passwords(heralding)'] == (3)+fillupES


def test_tpotStats(client):
    # [GET] /alert/TpotStats ==> Returns statistics on T-Pot community installations. Parameter: day=YYYYMMDD, e.g. /alert/TpotStats?day=20180317
    day = datetime.datetime.now().strftime('%Y%m%d')
    response = client.get("/alert/TpotStats?day="+day)
    print(response.get_json())
    assert response.get_json()['communityHoneypots']['numberAlertsPerType']['Network(dionaea)'] == 1
    assert response.get_json()['communityHoneypots']['numberAlertsPerType']['Passwords(heralding)'] == len(es_data)-2
    assert response.get_json()['communityHoneypots']['numberHoneypotsPerType']['Network(dionaea)'] == 1
    assert response.get_json()['communityHoneypots']['numberHoneypotsPerType']['Passwords(heralding)'] == 1
    assert response.get_json()['communityHoneypots']['totalNumberAlerts'] == len(es_data)-1
    assert response.get_json()['communityHoneypots']['totalNumberDaemons'] == 2
    assert response.get_json()['communityHoneypots']['totalNumberHoneypots'] == 1

#### TODO

# def test_retrieveLatLonAttacks(client):
#     # KAPUTT????
#     #########################################
#     # [GET] /alert/retrieveLatLonAttacks ==> Returns top X count on Lat and Lng. use GET parameter "offset" and "topx" to determine the offset from now in days (default: last 24h) and how many results shall be returned (default: top10). Use parameter "direction" to determine if source or destination location is given.
#     response = client.get("/alert/retrieveLatLonAttacks")
#     assert response.status_code == 200
#     print(response.get_json())
#
#     assert False








# [GET] /alert/getStats ==> Returns detailed statistics on T-Pot community data. Parameter:
# gte=YYYY-MM-DD HH:MM:SS => from timestamp, url-encoded, defaults to last 24h if missing
# lt=YYYY-MM-DD HH:MM:SS => to timestamp, url-encoded, defaults to now() if missing
# value=<honeypot-type1,honeypot-type2...> => 0 .. n honeypot types, comma-separated, url-encoded, choose from:
#      - 'E-Mail(mailoney)',
#      - 'Industrial(conpot)',
#      - 'Network(cisco-asa)',
#      - 'Network(Dionaea)',
#      - 'Network(honeytrap)',
#      - 'Network(suricata)',
#      - 'Passwords(heralding)',
#      - 'RDP(rdpy)',
#      - 'SSH/console(cowrie)',
#      - 'Service(ES)',
#      - 'Service(emobility)',
#      - 'Service(Medicine)',
#      - 'VNC(vnclowpot)',
#      - 'Webpage',
#      - 'Unclassified'
# example: /alert/getStats?values=Network(Dionaea),Network(honeytrap),SSH%2Fconsole(cowrie),Unclassified&lt=2019-01-22+15%3A24%3A52&gte=2019-01-22+15%3A30%3A07







# [GET] /alert/tops ==> Returns detailed statistics on topx urls and destination ports in timeframe. Parameter type {urls,destports}, days {1,7,28} and topx {1...30}, e.g. /alert/tops?type=urls&topx=5&days=28
