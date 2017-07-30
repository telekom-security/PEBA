Install

pip3 install -r requirements.txt 

python3 worker.py -p 9933 -b 192.168.1.64 -s 192.168.1.64 -i ews-2017.1


Command line option

-p local port to listen on
-b local ip / interface to listen on
-s ip of elasticsearch
-i index to be used on elasticsearch server
-mh mongohost
-mp mongoport
-g use gunicorn server
-c just create the index

Credits

Some auth code by Andre Vorbach

Used frameworks / tools: