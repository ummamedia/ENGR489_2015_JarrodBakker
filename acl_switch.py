# Author: Jarrod N. Bakker
# Part of an ENGR489 project at Victoria University of Wellington
# during 2015.
#
# This file manages the flow table and keeps an ACL. When we see
# a new flow, we check it against the ACL and decide if we allow
# or drop the packet from there.
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


class ACLSwitch(app_manager.RyuApp):
    # Constants
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Fields
    access_control_list = []

    def __init__(self, *args, **kwargs):
        super(ACLSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        #self.rule_input()
        self.access_control_list.append(("10.0.0.1","10.0.0.3"))
        print self.access_control_list
    
    def rule_input(self):
        # Continuously wait for the user to input rules for blocking
        # traffic.
        while True:
            rule = raw_input("Rule ::= Source IP, Destination IP\n ")
            print str(rule)

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
            # verify if we have a valid buffer_id, if yes avoid to send both
            
            print ("\nNew flow detected, checking ACL.\n")
            # Assume IPv4 packets only
            # TODO add IPv6 support
            data = pkt.get_protocols(ipv4.ipv4)
            if (data):
                ipv4_head = data[0]
                print "IPv4 Header: " + str(ipv4_head)
                ipv4_dst = ipv4_head.dst
                ipv4_src = ipv4_head.src
               # print str(ipv4_dst) + " " + str(ipv4_src)
                for rule in self.access_control_list:
                    if (ipv4_src == rule[0] and ipv4_dst == rule[1] ):
                        print "Found a match!"

            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
