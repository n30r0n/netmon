import pyshark 
from getmac import get_mac_address
import requests 
import ifcfg
import datetime

opf = open('netmon.log', 'a')
def parse_names(name):
    if len(name) >= 7:
        if 'wireless' in name.lower():
            return 'wi-fi 2'
def get_adapter():
    ifaces = list(ifcfg.interfaces())
    for name in ifaces: 
        ifc = ifcfg.interfaces().get(name) 
        if ifc['inet'] != None:
            return name

ip = lambda packet : packet['IP'].src if torf == True else False 
dns_name = lambda packet : packet['DNS'].qry_name if torf == True else False
dname = lambda mac : requests.get("https://api.macvendors.com/"+mac).text

capture = pyshark.LiveCapture(interface=parse_names(get_adapter()), display_filter='dns')
for raw_packet in capture.sniff_continuously():
    torf = True if 'DNS' in raw_packet else False
    log = f'{datetime.datetime.now().strftime("%H:%M:%S")} - {ip(raw_packet)} : {dname(get_mac_address(ip=ip(raw_packet)))} : {dns_name(raw_packet)}'
    opf.write(log+'\n')
    print(log)
opf.close()