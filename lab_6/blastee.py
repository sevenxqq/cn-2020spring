#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time

def getPara():
    for rawline in open("lab_6/blastee_params.txt","r"): #设置文件对象并读取
        if not rawline :
            break
        line = rawline.strip()  #format: -b ip -n num
        if not line:
            continue
        (temp1,ip, temp2,num1) = line.split(' ')
        num1=int(num1)
        return ip,num1

def mk_ack(hwsrc, hwdst, ipsrc, ipdst, ttl=64):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP  #ether head
    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
    ippkt.dst = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.UDP
    ippkt.ttl = ttl
    ippkt.ipid = 0      # ipv4 head
    udppkt=UDP()
    udppkt.src=6666
    udppkt.dst=7777
    return ether + ippkt + udppkt 

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    blasterIp,num=getPara()
    log_info("ip:{},num:{}".format(blasterIp,num))
    blasterMac='10:00:00:00:00:01'
    blasteeMac='20:00:00:00:00:01'
    blasteeIp='192.168.200.1'
    acknum=0
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
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))
            ackpkt=mk_ack(blasteeMac,blasterMac,blasteeIp,blasterIp,64)
            xpkt=pkt[RawPacketContents]
            log_info("xpkt={}".format (xpkt))
            seqNum=xpkt._raw[:4]
            log_info("seq={}".format (seqNum))
            payLoad=pkt[RawPacketContents]._raw[6:14]
            ackpkt=ackpkt+ seqNum + payLoad
            net.send_packet(dev,ackpkt)
            acknum+=1
            if(acknum>=num):
                break
    net.shutdown()
