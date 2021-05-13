#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        dic=dict()
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                if pkt.has_header(Arp)==True:
                    arp = pkt.get_header(Arp)
                    dic[str(arp.senderprotoaddr)]=str(arp.senderhwaddr)
                    log_info("add/update an entry ip :{} , mac,{}".format(arp.senderprotoaddr,arp.senderhwaddr))
                    if arp.operation==ArpOperation.Request: #if it's an arp request
                        srcip=arp.targetprotoaddr
                        my_interfaces = self.net.interfaces() 
                        for intf in my_interfaces: 
                            if srcip == intf.ipaddr:
                                srchw=intf.ethaddr
                                dstip=arp.senderprotoaddr
                                arpre=create_ip_arp_reply(srchw, arp.senderhwaddr, srcip, dstip)
                                self.net.send_packet(dev,arpre)  #from which port get then send it at that port


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
