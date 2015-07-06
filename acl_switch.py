# Author: Jarrod N. Bakker
# Part of an ENGR489 project at Victoria University of Wellington
# during 2015.
#
# This file manages the flow table and keeps an ACL. When we see
# a new flow, we check it against the ACL and decide if we allow
# or drop the packet from there. This stateless firewall will
# proactively send the rules to the switches.
#
# Because rules which block traffic are important to the security
# of a network, the priority of such rules should be higher than
# the rules which allow traffic to flow. Currently, the default
# priority value is used for rules which allow traffic and the max
# value is used for rules which block traffic. Later on it may be
# possible to specify custom priorities.
#
# The RESTful interface code is adapted from
# http://osrg.github.io/ryu-book/en/html/rest_api.html.
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

# TODO fix same function naming convention issues...

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
# I have added the below libraries to this code
# Packet stuff
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
import socket, struct
# REST interface
import json
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
# Other
from collections import namedtuple
from ryu.app.ofctl import api

acl_switch_instance_name = "acl_switch_app"
url = "/acl_switch"

class ACLSwitch(app_manager.RyuApp):
    # Constants
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    OFP_MAX_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY*2 - 1
            # Default priority is defined to be in the middle (0x8000 in 1.3)
            # Note that for a priority p, 0 <= p <= MAX (i.e. 65535)
    ACL_ENTRY = namedtuple("ACL_ENTRY", "ip_src ip_dst tp_proto port_src port_dst")
    _CONTEXTS = {"wsgi":WSGIApplication}

    # Fields
    access_control_list = []
    connected_switches = []

    def __init__(self, *args, **kwargs):
        super(ACLSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        filename = "ryu/ENGR489_2015_JarrodBakker/rules.acl"
        try:
            self.import_from_file(filename)
        except:
            print "[-] ERROR: could not open file \'" + str(filename) + "\'"
        print self.access_control_list
        wsgi = kwargs['wsgi']
        wsgi.register(ACLSwitchRESTInterface, {acl_switch_instance_name : self})

    def import_from_file(self, filename):
        buf_in = open(filename)
        for line in buf_in:
            items = line.split(", ")
            items[len(items)-1] = items[len(items)-1][:-1] # trim \n from input
            self.add_ACL_Rule(items[0], items[1], items[2], items[3], items[4])

    # Add a rule to the ACL. 
    def add_ACL_Rule(self, ip_src, ip_dst, tp_proto, port_src, port_dst):
            newRule = self.ACL_ENTRY(ip_src=ip_src, ip_dst=ip_dst,
                                     tp_proto=tp_proto, port_src=port_src,
                                     port_dst=port_dst)
            self.access_control_list.append(newRule)
            #self.distributeSingleRule(newRule)
            return newRule
    
    # Proactively distribute a newly added rule to all connected switches
    def distribute_Single_Rule(self, rule):
        for switch in self.connected_switches:
            datapath = api.get_datapath(self, switch)
            parser = datapath.ofproto_parser
            # follow code in distributeRulesStartup
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

    # Proactively distribute hardcoded firewall rules to the switches.
    # NOTE This is mainly used for testing rules or if a new switch joins
    #      the network later on.
    # @param datapath - an OF enabled switch to communicate with
    # @param parser - parser for the switch passed through in datapath
    def distribute_Rules_Startup(self, datapath, parser):
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
        self.distribute_Rules_Startup(datapath, parser)

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

    # The incoming flow has IPv4. Search through the ACL for a match and 
    # return the correct OF match and actions.
    # @return - if a rule in the ACL is found: the matching rules and
    #           actions for the switches to follow, otherwise False.
    # TODO have a separate ACL for IPv4 ad IPv6
    # TODO instead of flows being installed here, have this function return the actions and match etc.
    def ipv4_match(self, packet, ipv4_head, parser):
        #print "[+] IPv4 Header: " + str(ipv4_head)
        ipv4_src = ipv4_head.src
        ipv4_dst = ipv4_head.dst
        # port numbers may not be needed but they are declared for scoping
        port_src = ""
        port_dst = ""
        # Assume TCP TODO add UDP support
        if ipv4_head.proto == ipv4.inet.IPPROTO_TCP:
            tcp_head = packet.get_protocols(tcp.tcp)[0]
            port_src = str(tcp_head.src_port)
            port_dst = str(tcp_head.dst_port)
        # Get layer 4 data (if it exists)
        for rule in self.access_control_list:
            # TODO handle port numbers (not ranges of). Need to define syntax for port numbers, say if you don't specify a port number.
            # If a rule doesn't have port numbers specified (i.e. block all
            # TCP/UDP/both traffic) then only match on IPv4 address.
            if (rule.port_src == "*" and rule.port_dst == "*"):
                if (ipv4_src == rule.ip_src and ipv4_dst == rule.ip_dst):
                    # We have found flow which matches a rule in the ACL.
                    print "[-] ACL Match found (IP): creating action to block traffic."
                    priority = self.OFP_MAX_PRIORITY
                    # Create the matching rule for OF switches. Note that
                    # ip_proto is not used for matching as this will allow ARP
                    # packets through after a period of time.
                    match = parser.OFPMatch(eth_type = ethernet.ether.ETH_TYPE_IP,
                                            ipv4_src = rule.ip_src,
                                            ipv4_dst = rule.ip_dst)
                    # A match with empty actions means that the switch
                    # should drop packets within the flow
                    actions = []
                    # Return 
                    return (priority, match, actions)
            # Block flow based IPv4 address and port numbers
            else:
                print rule
                if (ipv4_src == rule.ip_src and ipv4_dst == rule.ip_dst
                    and port_src == rule.port_src
                    and port_dst == rule.port_dst):
                    # We have found flow which matches a rule in the ACL.
                    print "[-] ACL Match found (IP -> TCP): creating action to block traffic."
                    priority = self.OFP_MAX_PRIORITY
                    # Create the matching rule for OF switches. Note that
                    # ip_proto is not used for matching as this will allow ARP
                    # packets through after a period of time.
                    match = parser.OFPMatch(eth_type = ethernet.ether.ETH_TYPE_IP,
                                            ipv4_src = rule.ip_src,
                                            ipv4_dst = rule.ip_dst,
                                            ip_proto = ipv4.inet.IPPROTO_TCP,
                                            tcp_src = int(rule.port_src),
                                            tcp_dst = int(rule.port_dst)) # NOTE expecting an int here?
                    # A match with empty actions means that the switch
                    # should drop packets within the flow
                    actions = []
                    # Return 
                    return (priority, match, actions)   
        # A match was not found so return False
        return False

    # The incoming flow has IPv6. Search through the ACl for a match.
    # @return - if a match was found (True) or not (False)
    # TODO add support for IPv6
    def ipv6_flow(self, ipv6_head, datapath, match, actions, message, ofproto):
        ipv6_found_acl_match = False
        return ipv_found_acl_match

    # The incoming flow does not match any rule in the ACL. Therefore add a
    # rule which allows the traffic to flow through.
    # @return - if the buffer_id is valid (True) or not (False)
    # TODO does this function need the entire event message or just the 
    # buffer id? (just in case)
    def allow_flow(self, datapath, priority, match, actions, message, ofproto):
        # verify if we have a valid buffer_id, if yes avoid to send both
        # flow_mod & packet_out
        if message.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, priority, match, actions, message.buffer_id)
            return False
        else:
            self.add_flow(datapath, priority, match, actions)
        return True

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
            # Assume IPv4 packets only
            # TODO add IPv6 support
            # TODO block traffic in one direction
            # NOTE I can check for IPv4 by checking eth.proto
            data = pkt.get_protocols(ipv4.ipv4)
            if (data):
                ipv4_head = data[0]
                pma = self.ipv4_match(pkt, ipv4_head, parser) # Priority Match Action
                print "[#] " + str(pma) + "\n"
            #    found_acl_match = self.ipv4_flow(ipv4_head, datapath, match, actions, msg, ofproto);
            #    if found_acl_match == False:
            #        priority = 1
            #        if self.allow_flow(datapath, priority, match, actions, msg, ofproto) == False:
            #            return
            
                # If a match was found in the ACL, then the new flow must
                # have the associated match rules and actions assigned to it.
                if pma != False:
                    priority = pma[0]
                    match = pma[1]
                    actions = pma [2]
                    # TODO this makes an error happen: OFPET_BAD_MATCH code 9 (a prerequisite was not met)

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

# This class manages the RESTful API calls to add rules etc.
class ACLSwitchRESTInterface(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(ACLSwitchRESTInterface, self).__init__(req, link, data, **config)
        self.acl_switch_inst = data[acl_switch_instance_name]
    
    # example: curl -X GET http://127.0.0.1:8080/acl_switch
    @route("acl_switch", url, methods=["GET"])
    def return_acl(self, req, **kwargs):
        acl = self.acl_switch_inst.access_control_list
        body = json.dumps(acl)
        return Response(content_type="application/json", body=body)

    # example: curl -X PUT -d '{"ip_src":"10.0.0.2", "ip_dst":"10.0.0.3", "tp_proto":"*", "port_src":"*", "port_dst":"*"}' http://127.0.0.1:8080/acl_switch
    @route("acl_switch", url, methods=["PUT"])
    def add_rule(self, req, **kwargs):
        ruleReq = eval(req.body)
        newRule = self.acl_switch_inst.add_ACL_Rule(ruleReq["ip_src"],
                                                    ruleReq["ip_dst"],
                                                    ruleReq["tp_proto"],
                                                    ruleReq["port_src"],
                                                    ruleReq["port_dst"])
        self.acl_switch_inst.distribute_Single_Rule(newRule)

