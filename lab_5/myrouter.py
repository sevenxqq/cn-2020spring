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

dic=dict()  #ip : mac
fowardTable=[]
dq=[]   #cache those pkt that send arp request:(arp requestpkt),pkt,port,(nHOP port),inport(the port get the pkt)
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

def ifNewEntry(arprqt,pkt,portname,self,inport):
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
                    temp.append(inport)
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
        temp.append(inport)
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
            else:
                arpTable[i][2]=-1
                len2=len(dq)
                for j in range(len2):
                    if dq[j][0]==arpTable[i][0]:
                        my_interfaces = self.net.interfaces() 
                        myport=my_interfaces[0] #the port which get the pkt
                        for intf in my_interfaces: 
                            if dq[j][3]==intf.name:
                                myport=intf
                        newpkt=mk_icmperr(myport.ethaddr,"00:00:00:00:00:00",myport.ipaddr,dq[j][1][IPv4].src,ICMPType.DestinationUnreachable,1,dq[j][1],64)
                        ipv4_process(newpkt,self,0)
    #del pkts send successfully and arprqt
    
    for i in range (len1-1,-1,-1):
        if arpTable[i][2]==-1 :
            len2=len(dq)
            for j in range(len2-1,-1,-1):
                if dq[j][0]==arpTable[i][0]:
                    del dq[j]
            del arpTable[i]


        

    
def mk_ping(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=64, payload=''):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
    ippkt.dst = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    if reply:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoReply
        icmppkt.icmpcode = ICMPCodeEchoReply.EchoReply
    else:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoRequest
        icmppkt.icmpcode = ICMPCodeEchoRequest.EchoRequest
    icmppkt.icmpdata.sequence = 42
    icmppkt.icmpdata.data = payload
    return ether + ippkt + icmppkt 

def mk_icmperr(hwsrc, hwdst, ipsrc, ipdst, xtype, xcode=0, origpkt=None, ttl=64):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
    ippkt.dst = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    icmppkt = ICMP()
    icmppkt.icmptype = xtype
    icmppkt.icmpcode = xcode
    if origpkt is not None:
        xpkt = deepcopy(origpkt)
        i = xpkt.get_header_index(Ethernet)
        if i >= 0:
            del xpkt[i]
        icmppkt.icmpdata.data = xpkt.to_bytes()[:28]
        icmppkt.icmpdata.origdgramlen = len(xpkt)

    return ether + ippkt + icmppkt 

def ipv4_process(pkt,self,inport):
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
                ifNewEntry(arprqt,pkt,port.name,self,inport)
        else:   
            if nHop in dic: 
                destmac=dic[nHop]
                pkt[Ethernet].dst=destmac
                self.net.send_packet(port.name,pkt) 
            else:
                #send arp request
                arprqt=create_ip_arp_request(port.ethaddr, port.ipaddr, nHop)
                ifNewEntry(arprqt,pkt,port.name,self,inport)

def arp_process(pkt,self,dev):
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


class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
         
        
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
                    arp_process(pkt,self,dev)                                  
                #ipv4 packet
                if pkt.has_header(IPv4)== True:
                    ip=pkt.get_header(IPv4)
                    index=longmatch(ip.dst)
                    log_info(" ip.src: {} ,ip.dst: {} ".format(ip.src,ip.dst))
                    my_interfaces = self.net.interfaces() 
                    sendToRouter=False
                    targetport=my_interfaces[0]
                    port=my_interfaces[0] #the port which get the pkt
                    for intf in my_interfaces: 
                        if ip.dst==intf.ipaddr:
                            targetport=intf
                            sendToRouter=True
                        if dev==intf.name:
                            port=intf
                    
                    if index==-1: #no match entry
                        newpkt=mk_icmperr(port.ethaddr,"00:00:00:00:00:00",port.ipaddr,ip.src,ICMPType.DestinationUnreachable,0,pkt,64)
                        ipv4_process(newpkt,self,port)
                    else:
                        if sendToRouter==True: 
                            portReach=False
                            if pkt.has_header(ICMP)==True:
                                # echo request,  send echo reply   
                                if pkt[ICMP].icmptype == ICMPType.EchoRequest: 
                                    portReach=True             
                                    newpkt=mk_ping(targetport.ethaddr,"00:00:00:00:00:00",targetport.ipaddr,ip.src,True,64,'')
                                    newpkt[ICMP].icmpdata.sequence = pkt[ICMP].icmpdata.sequence 
                                    newpkt[ICMP].icmpdata.data = pkt[ICMP].icmpdata.data     
                                    ipv4_process(newpkt,self,port)  
                            if portReach==False:                          
                                #port unreachable
                                newpkt=mk_icmperr(port.ethaddr,"00:00:00:00:00:00",port.ipaddr,ip.src,ICMPType.DestinationUnreachable,3,pkt,64)
                                ipv4_process(newpkt,self,port)   

                        else:#sendToRouter=False
                            if(ip.ttl<=1):#reach the router and then expired
                                newpkt=mk_icmperr(port.ethaddr,"00:00:00:00:00:00",port.ipaddr,ip.src,ICMPType.TimeExceeded,ICMPCodeTimeExceeded.TTLExpired,pkt,64)
                                ipv4_process(newpkt,self,port)
                            else:
                                ipv4_process(pkt,self,port)     
                                                      
                                                                                     
def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    constructTable(net)
    r.router_main()
    net.shutdown()
