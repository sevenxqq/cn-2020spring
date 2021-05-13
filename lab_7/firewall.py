from switchyard.lib.userlib import *
import time

def switchForParse(line):
    entry=[]
    if "ip" in line and ('ratelimit' not in line):
        (operation, headerName, src , srcnet, dst ,dstnet) = line.split(' ')
        for i in range(6):  #these are all strings
            if i!=2 and i!=4:#0,1,  2:srcnet 3:dstnet
                entry.append(line.split(' ')[i])
        return entry
    elif  (('udp' in line) or ("tcp" in line))    and  (('ratelimit' not in line) and ('impair' not in line)):
        (operation, headerName, src , srcnet, port1,srcport ,dst ,dstnet,port2,dstport) = line.split(' ')
        for i in range(10):  #these are all strings
            if i==0 or i%2==1 :#0,1,    2:srcnet 3:srcport 4:dstnet 5:dstport
                entry.append(line.split(' ')[i])
        return entry
    elif ('tcp'in line or 'udp' in line) and ('ratelimit' in line):
        (operation, headerName, src , srcnet, port1,srcport ,dst ,dstnet,port2,dstport,rate,byterate) = line.split(' ')
        for i in range(10):  #these are all strings
            if i==0 or i%2==1 :#0,1,2:srcnet 3:srcport 4:dstnet 5:dstport
                entry.append(line.split(' ')[i])
        byterate=int(byterate)  # attention,it's int
        entry.append(0)  #6: ratelimit
        entry.append(byterate/2)   # 7: every 0.5s add rings into bucket
        entry.append(time.time())   #8:the add time
        return entry

    elif ('tcp'in line or 'udp' in line) and ('impair' in line):
        (operation, headerName, src , srcnet, port1,srcport ,dst ,dstnet,port2,dstport,tag) = line.split(' ')
        for i in range(10):  #these are all strings
            if i==0 or i%2==1 :#0,1,2:srcnet 3:srcport 4:dstnet 5:dstport
                entry.append(line.split(' ')[i])
        entry.append(tag)       #6 impair
        return entry
    elif 'icmp' in line and 'ratelimit' in line:
        (operation, headerName, src , srcnet, dst ,dstnet,rate,byterate) = line.split(' ')
        for i in range(6):  #these are all strings
            if i==0 or i%2==1 :#0,1,2:srcnet 3 :dstnet 
                entry.append(line.split(' ')[i])
        byterate=int(byterate)  # attention,it's int
        entry.append(0)  #4: ratelimit,ringbkt
        entry.append(byterate/2)   # 5: every 0.5s add rings into bucket
        entry.append(time.time())   #6:the add time
        return entry
    elif 'icmp' in line and 'ratelimit' not in line:
        (operation, headerName, src , srcnet, dst ,dstnet) = line.split(' ')
        for i in range(6):  #these are all strings
            if i==0 or i%2==1 :#0,1,2:srcnet 3 :dstnet 
                entry.append(line.split(' ')[i])
        return entry
    entry.append("none")
    return entry

def ruleParse():
    ruleTable=[]
    ruleTable.append("rules")
    for rawline in open("lab_7/firewall_rules.txt","r"): #设置文件对象并读取每一行文件
        if not rawline :
            break
        line = rawline.strip()
        if not line:
            continue
        if(line[0]!='#'):    #regardless the annotation
            entry = switchForParse(line)
            if entry[0] != 'none':
                ruleTable.append(entry)
    return ruleTable

def ipProc(ipsrc, ipdst , srcnet , dstnet):
    match = True    #whether matches the rule
    if srcnet!='any':
        srcnetw =IPv4Network(srcnet, strict=False) #
        match= ipsrc in srcnetw
    if match == False:
        return match
    if dstnet!='any':
        dstnetw=IPv4Network(dstnet, strict=False)    #
        match = ipdst in dstnetw
    return match

def portMatch (srcport,dstport,port1,port2):
    if port1!='any':
        if srcport!=int(port1):
            return False
    if port2!='any':
        if dstport !=int(port2):
            return False
    return True

def tcp_udp_Proc(ipsrc,srcport ,ipdst,dstport, srcnet, port1,dstnet,port2):
    # check if ip is match
    match = ipProc(ipsrc,ipdst,srcnet,dstnet)
    if match==False:
        return False
    match =portMatch(srcport,dstport,port1,port2)
    return match


def checkRule(ruleTable, pkt,net ,portpair,input_port ):
    if pkt.has_header(IPv4)== False:
        net.send_packet(portpair[input_port], pkt)
        return
    ipsrc = pkt[IPv4].src
    ipdst = pkt[IPv4].dst
    for entry in ruleTable:
        if entry[1]=='ip':
            if ipProc(ipsrc, ipdst , entry[2],entry[3]) == True:
                if entry[0]=='permit':
                    net.send_packet(portpair[input_port], pkt)
                return
        elif entry[1]=='tcp' and pkt.has_header(TCP) ==True :
            srcport=pkt[TCP].src
            dstport=pkt[TCP].dst
            if tcp_udp_Proc(ipsrc,srcport ,ipdst,dstport, entry[2],entry[3],entry[4],entry[5]) == True:
                if entry[0]=='permit':
                    if len(entry)==9:   #has ratelimit
                        size=len(pkt)
                        if pkt.has_header(Ethernet):
                            size-=(len(pkt[Ethernet]))
                        if size <= entry[6]:
                            entry[6]-=size
                        else:
                            return
                    elif len(entry)==7 and entry[6]== 'impair':
                        payload=''
                        newpayload=str(len(pkt))   #change payload to the len of pkt
                        newpayload=RawPacketContents(newpayload)
                        if pkt.has_header(RawPacketContents)==False:
                            log_info("before impair,payload='' ")
                            pkt+=newpayload
                        else:
                            payload=pkt[RawPacketContents]
                            log_info("before impair,payload={}".format(payload))
                            indexi = pkt.get_header_index(RawPacketContents)
                            pkt[indexi]=newpayload
                        log_info("after impair,payload={}".format(newpayload))
                    net.send_packet(portpair[input_port], pkt)
                return
                
        elif entry[1]=='udp' and pkt.has_header(UDP)==True:
            srcport=pkt[UDP].src
            dstport=pkt[UDP].dst
            if tcp_udp_Proc(ipsrc,srcport ,ipdst,dstport, entry[2],entry[3],entry[4],entry[5]) == True:
                if entry[0]=='permit':
                    if len(entry)==9:   #has ratelimit
                        size=len(pkt)
                        if pkt.has_header(Ethernet):
                            size-=(len(pkt[Ethernet]))
                        if size <= entry[6]:
                            entry[6]-=size
                        else:
                            return
                    net.send_packet(portpair[input_port], pkt)
                return 

        elif entry[1]=='icmp' and pkt.has_header(ICMP)==True:
            if ipProc(ipsrc, ipdst , entry[2],entry[3]) == True:
                if entry[0]=='permit':
                    if len(entry)==7:   #has ratelimit
                        size=len(pkt)
                        if pkt.has_header(Ethernet):
                            size-=(len(pkt[Ethernet]))
                        if size <= entry[4]:
                            entry[4]-=size
                            log_info("1 :size{},ratelimit{}".format(size,entry[4]))
                        else:
                            log_info("2:size{},ratelimit{}".format(size,entry[4]))
                            return
                    net.send_packet(portpair[input_port], pkt)
                return 
    
 


def addRing(ruleTable):
    size=len(ruleTable)
    for i in range (size):
        if len(ruleTable[i]) == 9: #tcp,udp: has ring bucket,attetion the max is 2r
            if time.time()-ruleTable[i][8] >=0.5:
                ruleTable[i][6]+=ruleTable[i][7]
                ruleTable[i][6] = min (ruleTable[i][6], 4*ruleTable[i][7])
                ruleTable[i][8]=time.time()
        elif ruleTable[i][1]=='icmp' and len(ruleTable[i])== 7: #icmp limit
            if time.time()-ruleTable[i][6] >=0.5:
                ruleTable[i][4]+=ruleTable[i][5]
                ruleTable[i][4] = min (ruleTable[i][4], 4*ruleTable[i][5])
                ruleTable[i][6]=time.time() #update time



def main(net):
    # assumes that there are exactly 2 ports
    portnames = [ p.name for p in net.ports() ]
    portpair = dict(zip(portnames, portnames[::-1]))
    ruleTable = ruleParse()
    while True:
        addRing(ruleTable)
        pkt = None
        try:
            timestamp,input_port,pkt = net.recv_packet(timeout=0.25)
        except NoPackets:
            pass
        except Shutdown:
            break

        if pkt is not None:

            # This is logically where you'd include some  firewall
            # rule tests.  It currently just forwards the packet
            # out the other port, but depending on the firewall rules
            # the packet may be dropped or mutilated.
            checkRule(ruleTable,pkt, net, portpair, input_port) 
    net.shutdown()
