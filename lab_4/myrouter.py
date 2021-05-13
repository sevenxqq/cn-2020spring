#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *
from switchyard.lib.address import *
from queue import Queue

fowardTable=[]
dq=[]   #cache those pkt that send arp request:#srchw,srcip,dstip (arp request pkt),pkt,port
arpTable=[] #cache arp request,last time,cnt,portname

def constructTable(net):
    for rawline in open("forwarding_table.txt","r"): #设置文件对象并读取每一行文件
        if not rawline :
            break
        line = rawline.strip()
        if not line:
            continue
        (prefix, mask, nextHop, port) = line.split(' ')
        temp=[]
        
        netaddr=prefix+'/'+mask
        netaddr=IPv4Network(netaddr) #entry:netaddr,length,nextHop,port
        temp.append(netaddr)
        temp.append(netaddr.prefixlen)
        temp.append(IPv4Address(nextHop))
        temp.append(port)
        fowardTable.append(temp)
    
    for intf in net.interfaces():   #the router intf
        temp=[]
        netaddr=intf.ipinterface.network
        temp.append(netaddr)
        temp.append(netaddr.prefixlen)
        temp.append("none")
        temp.append(intf.name)
        fowardTable.append(temp)    

def longmatch(destaddr):
    length=len(fowardTable)
    index=-1  # return the index of match entry
    leng=0
    for i in range(length):
        prefixnet=fowardTable[i][0]
        matches = destaddr in prefixnet
        if matches==True and fowardTable[i][1]>leng :
            index=i
            leng=fowardTable[i][1]
    return index

def ifNewEntry(arprqt,pkt,portname,self):
    hasIn1=False
    hasIn2=False
    len1=len(arpTable)
    for i in range (len1):
        if arpTable[i][0]==arprqt : # if had cache the arprqt,check if had cache the pkt
            hadIn1=True
            len2=len(dq)
            for j in range(len2):
                if dq[j][0]==arpTable[i][0]:
                    hasIn2=True
                    break
                if hasIn2==False : # cache the pkt
                    temp=[]
                    temp.append(arprqt)
                    temp.append(pkt)
                    temp.append(portname)
                    dq.append(temp)
            break
    if hasIn1==False: 
        #cache the arprqt
        temp1=[]
        temp1.append(arprqt)
        temp1.append(time.time())
        self.net.send_packet(portname,arprqt)    #send request
        temp1.append(1) 
        temp1.append(portname)  
        arpTable.append(temp1)
        #cache the pkt
        temp=[]
        temp.append(arprqt)
        temp.append(pkt)
        temp.append(portname)
        dq.append(temp)

def arpquery(self,mac):
    len1=len(arpTable)
    #check if there is a tag,send the pkt and then del the entry
    for i in range (len1):
        if arpTable[i][2]==-1:
            len2=len(dq)
            for j in range(len2):
                if dq[j][0]==arpTable[i][0]:
                    pkt=dq[j][1]
                    pkt[Ethernet].dst=mac
                    self.net.send_packet(dq[j][2],pkt)  
            
        else:   # no response
            if arpTable[i][2]<5:
                if time.time()-arpTable[i][1]>=1:   #has pass 1s,send again
                    self.net.send_packet(arpTable[i][3],arpTable[i][0])
                    arpTable[i][1]=time.time()
                    arpTable[i][2]+=1  #count++
    #del pkts send successfully and arprqt
    
    for i in range (len1-1,-1,-1):
        if arpTable[i][2]==-1 or arpTable[i][2]>=5:
            len2=len(dq)
            for j in range(len2-1,-1,-1):
                if dq[j][0]==arpTable[i][0]:
                    del dq[j]
            del arpTable[i]
    
class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        dic=dict()  #ip : mac 
        
        while True:
            arpquery(self,0)
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

                
                # arp packet
                if pkt.has_header(Arp)==True:
                    arp = pkt.get_header(Arp)
                    dic[arp.senderprotoaddr]=arp.senderhwaddr
                    log_info("add/update an entry ip :{} , mac,{}".format(arp.senderprotoaddr,arp.senderhwaddr))

                    #if it's an arp request
                    if arp.operation==ArpOperation.Request: 
                        srcip=arp.targetprotoaddr
                        my_interfaces = self.net.interfaces() 
                        for intf in my_interfaces: 
                            if srcip == intf.ipaddr:
                                srchw=intf.ethaddr
                                dstip=arp.senderprotoaddr
                                arpre=create_ip_arp_reply(srchw, arp.senderhwaddr, srcip, dstip)
                                self.net.send_packet(dev,arpre)  #from which port get then send it at that port

                    #if it's an arp reply
                    if arp.operation==ArpOperation.Reply: 
                        length=len(arpTable)
                        for i in range (length):
                            arprqt=arpTable[i][0].get_header(Arp)
                            #it's reply-request
                            if arprqt.targetprotoaddr==arp.senderprotoaddr and arprqt.senderprotoaddr==arp.targetprotoaddr:
                                if arpTable[i][2]<5:
                                #did't timeout
                                    if time.time()-arpTable[i][1]<1:
                                        arpTable[i][2]=-1 #tag has recv 
                                        #send those pkt get response
                                        arpquery(self,arp.senderhwaddr) 
                                    else: #timeout
                                        self.net.send_packet(arpTable[i][3],arpTable[i][0])    #send request again
                                        arpTable[i][1]=time.time()
                                        arpTable[i][2]+=1
                                break
                                    

                        

                #ipv4 packet
                if pkt.has_header(IPv4)== True:
                    ip=pkt.get_header(IPv4)
                    index=longmatch(ip.dst)
                    if index!=-1 :
                        pkt[IPv4].ttl-=1
                        nHop=fowardTable[index][2] 
                        my_interfaces = self.net.interfaces() 
                        port=my_interfaces[0]
                        for intf in my_interfaces:
                            if intf.name==fowardTable[index][3]:
                                pkt[Ethernet].src=intf.ethaddr
                                port=intf

                        if nHop== "none": #reach the last stop
                            if ip.dst in dic:
                                destmac=dic[ip.dst]
                                pkt[Ethernet].dst=destmac
                                self.net.send_packet(port.name,pkt) 
                            else:
                                #send arp request
                                arprqt=create_ip_arp_request(port.ethaddr, port.ipaddr, ip.dst)
                                ifNewEntry(arprqt,pkt,port.name,self)
                               

                        else:   
                            if nHop in dic: 
                                destmac=dic[nHop]
                                pkt[Ethernet].dst=destmac
                                self.net.send_packet(port.name,pkt) 
                            else:
                                #send arp request
                                arprqt=create_ip_arp_request(port.ethaddr, port.ipaddr, nHop)
                                ifNewEntry(arprqt,pkt,port.name,self)
                               
                                    

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    constructTable(net)
    r.router_main()
    net.shutdown()
