#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import time


#statement

def getPara():
    log_info("getpara")
    for rawline in open("lab_6/blaster_params.txt","r"): #设置文件对象并读取
        if not rawline :
            break
        line = rawline.strip()  #format: -b ip -n num -l length -w SW -t timeout -r recv_time
        if not line:
            continue
        (temp1,ip, temp2,num1,temp3,length,temp4,SW,temp5,time1,temp6,time2) = line.split(' ')
        num1=int(num1)
        length=int(length)
        SW=int(SW)
        time1=float(time1)
        time2=float(time2)
        return ip,num1,length,SW,time1,time2

def initPkt(num,hwsrc,hwdst,ipsrc,ipdst,length):
    log_info("initpkt")
    pkt = Ethernet() + IPv4() + UDP() 
    pkt[1].protocol = IPProtocol.UDP
    pkt[Ethernet].src=hwsrc
    pkt[Ethernet].dst=hwdst
    pkt[IPv4].src=ipsrc
    pkt[IPv4].dst=ipdst
    pkt[IPv4].ttl=64
    pkt[UDP].src=6666
    pkt[UDP].dst=7777       #three headers
    payload='a pkt send from blaster to blastee'
    for i in range(length):
        payload+='a'
    payload=payload[0:length]
    plraw=RawPacketContents(payload)
    lenraw=(length).to_bytes(2,'big')
    TotalPkt=[] 
    for i in range(1,num+1):
        seqraw=(i).to_bytes(4,'big') # i is the num,4 is bytenum,big-endian
        temp=[]
        temp.append(pkt)      #0:
        temp.append(seqraw)  #1:seqNum
        temp.append(lenraw)     #2
        temp.append(plraw)      #3
        temp.append(False) # 4: acked or not
        temp.append(False)  #5 :has been sent or not
        temp.append(0)  #6 :send time 
        TotalPkt.append(temp)
    return TotalPkt

def sendPkt(self,SW,left,right,timeout,net,num,renum):
    for i in range(left,left+SW):#seqnum begin 1,but i store it begin 0
        if i<=num and self[i-1][4]==False: #not been acked,total num pkts
            j=i-1
            if self[i-1][5]==True and time.time()-self[i-1][6]>timeout: #the timeout pkt is priority
                pkt=self[j][0]+self[j][1]+self[j][2]+self[j][3]
                net.send_packet("blaster-eth0",pkt)
                self[j][6]=time.time()
                renum+=1
                log_info("resend seq={}".format(i))
            elif self[j][5]==False:
                self[j][5]=True
                self[j][6]=time.time()
                pkt=self[j][0]+self[j][1]+self[j][2]+self[j][3]
                net.send_packet("blaster-eth0",pkt)
                right+=1
                log_info("send seq={}".format(i))
    return right,renum

def getPkt(self,pkt,timeOut,left,ackednum):
    log_info("getPkt")
    xpkt = pkt[RawPacketContents]._raw
    seqNum=xpkt[0:4]
    log_info("seq={}".format (seqNum))
    seq=int.from_bytes(seqNum,'big')
    if time.time()-self[seq-1][6]<=timeOut:
        if(self[seq-1][4])==False:
            ackednum+=1
            self[seq-1][4]=True #change ack tag
            if(seq==left):
                left+=1
    return left,ackednum


def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    blasterMac='10:00:00:00:00:01'
    blasteeMac='20:00:00:00:00:01'
    blasterIp='192.168.100.1'
    blateeIp,num,length,SW,timeOut,recvTime=getPara()
    Lhs=1
    Rhs=1
    ackedNum=0
    AllPkt=[]
    AllPkt=initPkt(num,blasterMac,blasteeMac,blasterIp,blateeIp,length)
    beginTime=time.time()
    REnum=0
    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            timestamp,dev,pkt = net.recv_packet(timeout=recvTime)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet")
            Lhs,ackedNum=getPkt(AllPkt,pkt,timeOut,Lhs,ackedNum)
        else:
            log_debug("Didn't receive anything")
            if ackedNum<num:
                Rhs,REnum=sendPkt(AllPkt,SW,Lhs,Rhs,timeOut,net,num,REnum)
                #log_info("lhs={},rhs:{}".format(Lhs,Rhs))
            else:
                endTime=time.time()
                TXtime=endTime-beginTime
                log_info("total time={}".format(TXtime))
                log_info("retransmitted num={}".format(REnum))
                log_info("timeout num={}".format(REnum))
                thrOut=length*(REnum+num)
                thrOut=float(thrOut)
                thrOut=thrOut/TXtime
                log_info("through put bps={}".format(thrOut))
                goodPut=length*num
                goodPut=float(goodPut)
                goodPut/=TXtime
                log_info("good put bps={}".format(goodPut))
                break

            '''
            Do other things here and send packet
            '''

    net.shutdown()
