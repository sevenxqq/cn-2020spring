'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    LearnTable=[]  #mac,port,volume
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        has_lrnsrc_befor=False
        has_lrndst_befor=False

        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            length=len(LearnTable)
            for i in range(length): # check if know the src / dest
                #log_info (" mac: {} port: {} volume:{}".format(LearnTable[i][0], LearnTable[i][1],LearnTable[i][2]))
                if LearnTable[i][0]==packet[0].src and has_lrnsrc_befor==False:
                    has_lrnsrc_befor=True
                    if LearnTable[i][1] != input_port:
                        LearnTable[i][1]=input_port
                        #log_info (" update mac: {} port: {} volume :{}".format(LearnTable[i][0], LearnTable[i][1],LearnTable[i][2]))
                    LearnTable[i][2]+=1

                if LearnTable[i][0] == packet[0].dst and has_lrndst_befor == False:
                    has_lrndst_befor = True
                    net.send_packet(LearnTable[i][1], packet)
            if has_lrnsrc_befor == False:   #add the src
                temp =[]
                temp.append(packet[0].src)
                temp.append(input_port)
                temp.append(1)
                if length < 5 :
                    LearnTable.append(temp)
                else:
                    lrt=LearnTable[4]
                    for i in range (4):
                       if LearnTable[i][2]<lrt[2]:
                           lrt=LearnTable[i]
                    #log_info (" delete LTV,mac: {} port: {},volume :{}".format(lrt[0],lrt[1],lrt[2]))
                    LearnTable.remove(lrt)
                    LearnTable.append(temp)
                #log_info (" add mac: {} port: {},volume :{}".format(temp[0], temp[1],temp[2]))
            if has_lrndst_befor == False:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
        
    net.shutdown()
