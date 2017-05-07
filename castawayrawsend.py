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
    spoofed_pkt = IP(src='192.168.1.144', dst=redirect_to)/UDP(dport='mdns', sport='mdns')/Raw(load=data_hex)

    send(spoofed_pkt)
    print 'Sent:', spoofed_pkt.summary()

## Define our Custom Action function
def customAction(packet):
    global packetCount
    packetCount += 1
    #print packet.show()
    if DNSQR in packet:
        if packet[DNSQR].qname == '_googlecast._tcp.local.':
            print 'chromecast is being looked for'
            #flip the QU bit to true
            dns_spoof(packet)
            return "Packet #%s: %s ==> %s" % (packetCount, packet[0][1].src, packet[0][1].dst)
## Setup sniff, filtering for IP traffic
#sniff(filter="ip", prn=customAction)
#sniff(filter="ip and udp port mdns", prn=customAction)

def main():
    dns_spoof("tst")

main()
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
