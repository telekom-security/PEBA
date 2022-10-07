# PEBA - Python EWS Backend API

## Implemented API-Endpoints

#### Private GET-Endpoints using authentication:

 - [POST] */alert/retrieveIPs* ==> returning the unique IP addresses of the last attacks in timeframe (default 120 minutes), a "Bad IP List". Can further be parametrized using out=json. Defaults to xml.
 - [POST] */alert/retrieveIPs15m* ==> returning the unique IP addresses of the last attacks in the last 15 minutes, a shorter "Bad IP List". Can further be parametrized using out=json. Defaults to xml.

 - [POST] */alert/retrieveAlertsCyber* ==> returning the last 1000 attacks, including IPs.
 - [POST] */alert/querySingleIP* ==> returns last 1000 attacks from IP. Set IP in GET parameter "ip", e.g. */querySingleIP?ip=8.8.8.8*

The above private endpoints cannot be queried using the community credentials (1), only by users of the private domain (2).

#### Public GET-Endpoints for Sicherheitstacho.eu:
 
 - [GET] */alert/retrieveAlertsCount* ==> returns the number of attacks within timespan in minutes or since the beginning of the current day e.g. */retrieveAlertsCount?time=10* or */retrieveAlertsCount?time=day*. Can further be parametrized using *out=json*. Defaults to xml.  
 - [GET] */alert/heartbeat* ==> Returns backend elasticsearch and memcached status
 - [GET] */alert/retrieveAlertsJson* ==> Returns last 35 Alerts in json for usage in sicherheitstacho
 - [GET] */alert/datasetAlertsPerMonth* ==> Returns attacks per day for */datasetAlertsPerMonth?days=x* in the last x days OR for the last month, defaults to last month, if no GET parameter "days" is given
 - [GET] */alert/datasetAlertTypesPerMonth* ==> Returns attacks / day, grouped by honeypot type, for */datasetAlertTypesPerMonth?days=x* in the last x days OR for the last month, defaults to last month, if no GET parameter "days" is given
 - [GET] */alert/retrieveAlertStats* ==> Returns combines statistics in one call: AlertsLastMinute, AlertsLastHour, AlertsLast24Hours
 - [GET] */alert/topCountriesAttacks* ==> Returns information on the Top 10 attacker countries and top 10 attacked countries. use GET parameter "offset" and "topx" to determine the offset from this month (default: this month) and how many results shall be returned (default: top10)
 - [GET] */alert/retrieveLatLonAttacks* ==> Returns top X count on Lat and Lng. use GET parameter "offset" and "topx" to determine the offset from now in days (default: last 24h) and how many results shall be returned (default: top10). Use parameter "direction" to determine if source or destination location is given.
 - [GET] */alert/retrieveAlertsCountWithType* ==> returns the number of attacks within timespan in minutes or since the beginning of the current day, grouped by Type, e.g. */retrieveAlertsCountWithType?time=10* or */retrieveAlertsCountWithType?time=day*. Returns json.
 - [GET] */alert/TpotStats* ==> Returns statistics on T-Pot community installations. Parameter: *day=YYYYMMDD*, e.g. */alert/TpotStats?day=20180317* 
 - [GET] */alert/getStats* ==> Returns detailed statistics on T-Pot community data. Parameter:    
   -  *gte=YYYY-MM-DD HH:MM:SS* => ***from*** timestamp, url-encoded, defaults to last 24h if missing
   -  *lt=YYYY-MM-DD HH:MM:SS* => ***to*** timestamp, url-encoded, defaults to now() if missing
   -  *value=<honeypot-type1,honeypot-type2...>* => ***0 .. n*** honeypot types, comma-separated, url-encoded, choose from:
              
               - 'E-Mail(mailoney)',
               - 'Industrial(conpot)',
               - 'Network(cisco-asa)',
               - 'Network(Dionaea)',
               - 'Network(honeytrap)',
               - 'Network(suricata)',
               - 'Passwords(heralding)',
               - 'RDP(rdpy)',
               - 'SSH/console(cowrie)',
               - 'Service(ES)',
               - 'Service(emobility)',
               - 'Service(Medicine)',
               - 'VNC(vnclowpot)',
               - 'Webpage',
               - 'Unclassified'
    example:  */alert/getStats?values=Network(Dionaea),Network(honeytrap),SSH%2Fconsole(cowrie),Unclassified&lt=2019-01-22+15%3A24%3A52&gte=2019-01-22+15%3A30%3A07* 
   
 - [GET] */alert/tops* ==> Returns detailed statistics on topx urls and destination ports in timeframe. Parameter *type* {urls,destports}, *days* {1,7,28} and topx {1...30}, e.g. */alert/tops?type=urls&topx=5&days=28*
 

## Data Domain

By default, querying the above endpoints, data from the **T-Pot community honeypots** is returned. To retrieve data from the **private domain honeypots**, add a GET parameter *ci=0*. To retrieve data from both domains,community and private, use *ci=-1*.

Example:  */alert/retrieveAlertsJson?ci=0* to retrieve the private json data feed. This works both on the public and private endpoints.

## Miscellaneous

### **Credits**

Developed by André Vorbach (vorband)  &  Markus Schmall (schmalle).

Overall help, friendly extensions / comments / suggestions by Markus Schroer and Robin Verton. Valuable discussions with Aydin Kocas, Markus Schroer, Marco Ochse, Robin Verton and Rainer Schmidt.

**Frameworks / tools**:

[Maxmind GeoIP](https://dev.maxmind.com/geoip/legacy/geolite/) - Gunicorn - Flask - Elasticsearch - Memcached

**Thanks**:

Lutz Wischmann from [42, The Software architects](http://www.software-architects.de/) and all people from [The Honeynet Project](https://www.honeynet.org/)

### Disclaimer

PEBA is published as it is without any liability as open source software. As with every piece of code, it may contain bugs. We will try to fix them as soon as we can verify the bugs, so please let us know when you find any. 

**It would have taken at least 42 bottles of Club-Mate to support the development of PEBA. However, we ran out of supplies. ;)**
