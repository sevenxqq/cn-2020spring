#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
from random import randint,random
import time

def getProp():
    for rawline in open("lab_6/middlebox_params.txt","r"): #设置文件对象并读取
        if not rawline :
            break
        line = rawline.strip()  #format: -d num1 -n num2:num1 is prop ,num2 is  dpktnum
        if not line:
            continue
        (prefix, num1, temp,pktnum) = line.split(' ')
        num1=float(num1)    #use a compare num, and everytime get a random num if it's less than num,drop pkt
        pktnum=int(pktnum) 
        return num1,pktnum


def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    blasterMac='10:00:00:00:00:01'
    blasteeMac='20:00:00:00:00:01'
    compNum,num=getProp()
    acknum=0
    log_info("possible :{} ".format(compNum))
    while True:
        gotpkt = True
        try:
            timestamp,dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet {}".format(pkt))

        if dev == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            randNum=random()
            if (randNum> compNum):
                pkt[Ethernet].dst=blasteeMac
                net.send_packet("middlebox-eth1", pkt)
        elif dev == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            '''
            pkt[Ethernet].dst=blasterMac
            net.send_packet("middlebox-eth0", pkt)
            acknum+=1
            if(acknum>=num):
                break
        else:
            log_debug("Oops :))")

    net.shutdown()
