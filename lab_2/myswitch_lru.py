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
    LearnTable=[]  #mac,port; in the list,the latter is the LRU
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
                #log_info (" mac: {} port: {}".format(LearnTable[i][0], LearnTable[i][1]))
                if LearnTable[i][0]==packet[0].src and has_lrnsrc_befor==False:
                    has_lrnsrc_befor=True
                    if LearnTable[i][1] != input_port:
                        LearnTable[i][1]=input_port
                        #log_info (" update mac: {} port: {}".format(LearnTable[i][0], LearnTable[i][1]))
                    temp=LearnTable[i]  
                    for j in range (i):
                        LearnTable [j+1]=LearnTable [j]
                    LearnTable[0]=temp

                if LearnTable[i][0] == packet[0].dst and has_lrndst_befor == False:
                    has_lrndst_befor = True
                    net.send_packet(LearnTable[i][1], packet)

            if has_lrnsrc_befor == False:   #add the src
                temp =[]
                temp.append(packet[0].src)
                temp.append(input_port)
                #log_info (" add mac: {} port: {}".format(temp[0], temp[1]))
                if length < 5 :
                    LearnTable.append(temp)
                else:
                    
                    for i in range (4):
                        LearnTable[i+1]=LearnTable[i]
                    LearnTable[0]=temp
                    #log_info (" delete LRU,add mac: {} port: {}".format(LearnTable[0][0], LearnTable[0][1]))

            if has_lrndst_befor == False:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
        #log_info ("finish a packet process")
    net.shutdown()
