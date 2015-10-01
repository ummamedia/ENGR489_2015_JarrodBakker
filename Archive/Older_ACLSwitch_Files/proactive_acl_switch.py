# Author: Jarrod N. Bakker
# Part of an ENGR489 project at Victoria University of Wellington
# during 2015.
#
# This file contains an proactive stateless SDN firewall. Rules are
# read in from a file and are distributed to switches as they
# connect with the controller. This version supports blocking on
# IPv4 addresses, TCP and UDP ports.
#
# Because rules which block traffic are important to the security
# of a network, the priority of such rules should be higher than
# the rules which allow traffic to flow. Currently, the default
# priority value is used for rules which allow traffic and the max
# value is used for rules which block traffic. Later on it may be
# possible to specify custom priorities.
#
# The original license for simple_switch_13.py can be found below.
#
####################################################################
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#####################################################################

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
# I have added the below libraries to this code
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib import hub
from collections import namedtuple
import socket, struct

class ACLSwitch(app_manager.RyuApp):
    # Constants
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    OFP_MAX_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY*2 - 1
            # Default priority is defined to be in the middle (0x8000 in 1.3)
            # Note that for a priority p, 0 <= p <= MAX (i.e. 65535)
    ACL_ENTRY = namedtuple("ACL_ENTRY", "ip_src ip_dst tp_proto port_src port_dst")

    # Fields
    access_control_list = []
    connected_switches = []

    def __init__(self, *args, **kwargs):
        super(ACLSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        filename = "ryu/ENGR489_2015_JarrodBakker/rules.acl"
        try:
            self.importFromFile(filename)
        except:
            print "[-] ERROR: could not open file \'" + str(filename) + "\'"
        print self.access_control_list

    def importFromFile(self, filename):
        buf_in = open(filename)
        for line in buf_in:
            items = line.split(", ")
            items[len(items)-1] = items[len(items)-1][:-1] # trim \n from input
            self.addACLRule(items[0], items[1], items[2], items[3], items[4])

    # Add a rule to the ACL. 
    def addACLRule(self, ip_src, ip_dst, tp_proto, port_src, port_dst):
            newRule = self.ACL_ENTRY(ip_src=ip_src, ip_dst=ip_dst,
                                     tp_proto=tp_proto, port_src=port_src,
                                     port_dst=port_dst)
            self.access_control_list.append(newRule)
            #print self.access_control_list
    
    # Proactively distribute hardcoded firewall rules to the switches.
    # NOTE This is mainly used for testing rules or if a new switch joins
    #      the network later on.
    # @param datapath - an OF enabled switch to communicate with
    # @param parser - parser for the switch passed through in datapath
    def distributeRulesStartup(self, datapath, parser):
        for rule in self.access_control_list:
            priority = self.OFP_MAX_PRIORITY
            actions = []
            match = None
            match = parser.OFPMatch()
            match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,
                               ethernet.ether.ETH_TYPE_IP)
            if (rule.ip_src != "*"):
                match.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC,
                                   struct.unpack("!I", socket.inet_aton(rule.ip_src))[0])
            if (rule.ip_dst != "*"):
                match.append_field(ofproto_v1_3.OXM_OF_IPV4_DST,
                                   struct.unpack("!I", socket.inet_aton(rule.ip_dst))[0])
            if (rule.tp_proto != "*"):
                if (rule.tp_proto == "tcp"):
                    match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                       ipv4.inet.IPPROTO_TCP)
                    if (rule.port_src != "*"):
                        match.append_field(ofproto_v1_3.OXM_OF_TCP_SRC,
                                           int(rule.port_src))
                    if (rule.port_src != "*"):
                        match.append_field(ofproto_v1_3.OXM_OF_TCP_DST,
                                           int(rule.port_dst))
                elif (rule.tp_proto == "udp"):
                    match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                       ipv4.inet.IPPROTO_UDP)
                    if (rule.port_src != "*"):
                        match.append_field(ofproto_v1_3.OXM_OF_UDP_SRC,
                                           int(rule.port_src))
                    if (rule.port_src != "*"):
                        match.append_field(ofproto_v1_3.OXM_OF_UDP_DST,
                                           int(rule.port_dst))
            if match == None:
                return
            self.add_flow(datapath, priority, match, actions)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        # The code below has been added by Jarrod N. Bakker
        # Take note of switches (via their datapaths)
        self.connected_switches.append(ev.msg.datapath_id)
        # Distribute the list of rules to the switch
        self.distributeRulesStartup(datapath, parser)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_head = pkt.get_protocols(ethernet.ethernet)[0]

        eth_dst = eth_head.dst
        eth_src = eth_head.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, eth_src, eth_dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][eth_src] = in_port

        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
            
            print "\n[+] New flow detected: checking ACL."
            print "[?] New flow packet: " + str(pkt)
            priority = ofproto_v1_3.OFP_DEFAULT_PRIORITY

            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, priority, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, priority, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
