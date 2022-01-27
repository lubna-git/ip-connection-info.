'''
this program for get information about the source and destination py using Wi-Fi or ethernet connection of your
computer
you have to pip install first:
-python-geoip-python3
-python-geoip-geolite2
-scapy
'''

import socket
from geoip import geolite2
from scapy.all import *
#get port name
def get_serv(scr_port,dst_port):
    try:
        service = socket.getservbyport(scr_port)
    except:
        service = socket.getservbyport(dst_port)
    return service
#get ip timezone and country
def locate(ip):
    loc = geolite2.lookup(ip)
    if loc is not None:
        return loc.country , loc.timezone
    else:
        return None

#get information of (packet = pkt)
def analyzer(pkt):
    try:
        # get source ip
        src_ip = pkt[IP].src
        # get destination ip
        dst_ip = pkt[IP].dst
        #get location of ip
        loc_src = locate(src_ip)
        loc_dst = locate(dst_ip)
        loc_ip = [loc_src,loc_dst]
        for x in loc_ip:
            if x is not None:
                country = x[0]
                timezone = x[1]
            else:
                country = 'UNKNOWN'
                timezone = 'UNKNOWN'
        #get mac address of ip
        mac_src = pkt.src
        mac_dst = pkt.dst
        # ip the type of protocol is
        if pkt.haslayer(ICMP):
            print('-----------------------------')
            print('ICMP PACKET....')
            print('SRC-IP: '+src_ip)
            print('DST-IP :'+dst_ip)
            print('SRC-MAC :'+mac_src)
            print('DST-MAC :'+mac_dst)
            print('TimeZone: '+timezone+'\ncountry: '+country)
            print('packet size: '+str(len(pkt))+'byte')
            # get the packet
            if pkt.haslayer(Raw):
                print(pkt[Raw].load)
            print('--------------------------------')
        else:
            #get the port of score and destination
            src_port = pkt.sport
            dst_port = pkt.dport
            service = get_serv(src_port,dst_port)
            if pkt.haslayer(TCP):
                print('--------------------------')
                print('TCP PACKET....')
                print('SRC-IP: ' + src_ip)
                print('DST-IP: ' + dst_ip)
                print('SRC-MAC :' + mac_src)
                print('DST-MAC: ' + mac_dst)
                print('SRC-PORT: '+str(src_port))
                print('DST-PRT: '+str(dst_port))
                print('SERVICE: '+service)
                print('TimeZone: ' + timezone + '\ncountry: ' + country)
                print('packet size: ' + str(len(pkt)) + 'byte')
                if pkt.haslayer(Raw):
                    print(pkt[Raw].load)
                print('----------------------------')
            elif pkt.haslayer(UDP):
                 print('--------------------------')
                 print('UDP PACKET....')
                 print('SRC-IP: ' + src_ip)
                 print('DST-IP: ' + dst_ip)
                 print('SRC-MAC :' + mac_src)
                 print('DST-MAC: ' + mac_dst)
                 print('SRC-PORT: ' + str(src_port) )
                 print('DST-PRT: ' + str(dst_port) )
                 print('SERVICE: ' + service)
                 print('TimeZone: ' + timezone + '\ncountry: ' + country)
                 print('packet size: ' + str(len(pkt)) + 'byte')
                 if pkt.haslayer(Raw):
                     print(pkt[Raw].load)
                 print('----------------------------')
    except:
        pass
print('**********START**********')
#iface is like interface connection
sniff(iface='Wi-Fi',prn = analyzer)







