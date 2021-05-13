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
    learnTable = []  #port,mac

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
        
        if packet[0].dst in mymacs:      #do nothing
            log_debug ("Packet intended for me")
        else:  
           
                for lrt in learnTable:
                    #log_info ("port: {} mac: {}".format(lrt[0], lrt[1]))
                    if packet[0].src == lrt[1]:
                        has_lrnsrc_befor=True   
                        if lrt[0]!=input_port:  # update port
                            lrt[0]=input_port
                    if lrt[1] == packet[0].dst and has_lrndst_befor==False:
                        net.send_packet(lrt[0], packet) 
                        has_lrndst_befor = True

                if has_lrnsrc_befor == False :
                    temp=[]
                    temp.append(input_port)
                    temp.append(packet[0].src)
                    learnTable.append(temp)

                if has_lrndst_befor == False :
                    for intf in my_interfaces: 
                        if input_port != intf.name:
                            log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                            net.send_packet(intf.name, packet)
        #log_info ("finish a packet process")
    net.shutdown()
