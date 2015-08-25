#!/bin/bash
# Start the network! Need to ensure that nothing is running first
sudo mn -c
#sudo ovs-vsctl set bridge s1 protocols=OpenFlow13 # not needed anymore!
sudo mn --topo tree,depth=2,fanout=2 --mac --controller remote --switch ovsk,protocols=OpenFlow13
