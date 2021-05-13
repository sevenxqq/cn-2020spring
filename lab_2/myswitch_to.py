'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
from time import *
def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    
    LearnTable=[]  #mac,port,timestamp
   
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
            
                for lrt in LearnTable:
                    if time()-lrt[2]>10:
                        LearnTable.remove(lrt)
                        #log_info (" delete port: {} mac: {}".format(lrt[0], lrt[1]))
                for lrt in LearnTable:
                    #log_info (" port: {} mac: {}".format(lrt[0], lrt[1]))
                    if lrt[0]==packet[0].src:
                        has_lrnsrc_befor=True
                        if lrt[1] == input_port:    #update src timestamp
                            lrt[2]=time()
                        else:
                            lrt[1]=input_port
                            lrt[2]=time()
                    if lrt[0]==packet[0].dst and has_lrndst_befor==False:
                        has_lrndst_befor=True
                        net.send_packet(lrt[1], packet)

                if has_lrnsrc_befor==False:
                    temp=[]
                    temp.append(packet[0].src)
                    temp.append(input_port)
                    temp.append(time())
                    LearnTable.append(temp)

                if has_lrndst_befor==False:
                    for intf in my_interfaces:
                        if input_port != intf.name:
                            log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                            net.send_packet(intf.name, packet)
        #log_info ("finish a packet process")
    net.shutdown()
