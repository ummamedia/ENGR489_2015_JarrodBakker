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
# The RESTful interface code has been adapted from
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

# TODO fix function naming convention inconsistencies

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
from ryu.lib.packet import ipv6
from ryu.lib.packet import tcp
from netaddr import IPAddress
import socket, struct
# REST interface
import json
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
# Other
from collections import namedtuple
from ryu.app.ofctl import api
import sys
from ryu.ofproto import ofproto_v1_3_parser as ofp13_parser

acl_switch_instance_name = "acl_switch_app"
url = "/acl_switch"

class ACLSwitch(app_manager.RyuApp):
    # Constants
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    OFP_MAX_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY*2 - 1
            # Default priority is defined to be in the middle (0x8000 in 1.3)
            # Note that for a priority p, 0 <= p <= MAX (i.e. 65535)
    ACL_ENTRY = namedtuple("ACL_ENTRY", "ip_src ip_dst tp_proto port_src port_dst")
            # Contains the connection 5-tuple and the OFPMatch instance for OF 1.3
    ACL_FILENAME = "ryu/ENGR489_2015_JarrodBakker/rules.json"
    _CONTEXTS = {"wsgi":WSGIApplication}

    # Fields
    access_control_list = {}
    acl_id_count = 0
    connected_switches = []

    def __init__(self, *args, **kwargs):
        super(ACLSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        try:
            self.import_from_file(self.ACL_FILENAME)
        except:
            print "[-] ERROR: could not read from file \'" + str(self.ACL_FILENAME) + "\'\n\t" + str(sys.exc_info())
        wsgi = kwargs['wsgi']
        wsgi.register(ACLSwitchRESTInterface, {acl_switch_instance_name : self})

    """
    Read in ACL rules from file filename. Note that the values passed
    through will have 'u' in front of them. This denotes that the string
    is Unicode encoded, as such it will affect the intended value.

    @param filename - the input file
    """
    def import_from_file(self, filename):
        buf_in = open(filename)
        for line in buf_in:
            if line[0] == "#":
                continue # Skip file comments
            rule = json.loads(line)
            self.add_acl_Rule(rule["ip_src"], rule["ip_dst"],
                              rule["tp_proto"], rule["port_src"],
                              rule["port_dst"])
    
    """
    Return the size of the ACL.

    @return - the size of the ACL
    """
    def acl_size(self):
        return len(self.access_control_list)

    """
    Create an OFPMatch instance based on the contents of an ACL_ENTRY.

    @param rule - the entry to create an OFPMatch instance from
    @return - the OFPMatch instance
    """
    def create_match(self, rule):
        match = ofp13_parser.OFPMatch()
        # Match IP layer (layer 3)
        if (IPAddress(rule.ip_src).version == 4):
            # Match IPv4
            match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,
                               ethernet.ether.ETH_TYPE_IP)
            if (rule.ip_src != "*"):
                match.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC,
                                    int(IPAddress(rule.ip_src)))
            if (rule.ip_dst != "*"):
                match.append_field(ofproto_v1_3.OXM_OF_IPV4_DST,
                                   int(IPAddress(rule.ip_dst)))
        else:
            # Match IPv6
            match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,
                               ethernet.ether.ETH_TYPE_IPV6)
            if (rule.ip_src != "*"):
                print"\n\n" + hex(IPAddress(rule.ip_src)) + "\n\n"
                match.append_field(ofproto_v1_3.OXM_OF_IPV6_SRC,
                                   IPAddress(rule.ip_src).words)
            if (rule.ip_dst != "*"):
                match.append_field(ofproto_v1_3.OXM_OF_IPV6_DST,
                                   IPAddress(rule.ip_dst).words)
        # Match transport layer (layer 4) 
        # Add IPv6 support - next header field must be used.
        if (rule.tp_proto != "*"):
            if (rule.tp_proto == "tcp"):
                # Match TCP
                match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                   ipv4.inet.IPPROTO_TCP)
                if (rule.port_src != "*"):
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_SRC,
                                       int(rule.port_src))
                if (rule.port_src != "*"):
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_DST,
                                       int(rule.port_dst))
            elif (rule.tp_proto == "udp"):
                # Match UDP
                match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                   ipv4.inet.IPPROTO_UDP)
                if (rule.port_src != "*"):
                    match.append_field(ofproto_v1_3.OXM_OF_UDP_SRC,
                                       int(rule.port_src))
                if (rule.port_src != "*"):
                    match.append_field(ofproto_v1_3.OXM_OF_UDP_DST,
                                       int(rule.port_dst))
        return match

    """
    Add a rule to the ACL by creating an entry then appending it to the list. 
    
    @param ip_src - the source IP address to match
    @param ip_dst - the destination IP address to match
    @param tp_proto - the Transport Layer (layer 4) protocol to match
    @param port_src - the Transport Layer source port to match
    @param port_dst - the Transport Layer destination port to match
    @return - a tuple indicating if the operation was a success, a message
              to be returned to the client and the new created rule. This
              is useful in the case where a single rule has been created
              and needs to be distributed among switches.
    """
    def add_acl_Rule(self, ip_src, ip_dst, tp_proto, port_src, port_dst):
        rule_id = str(self.acl_id_count)
        self.acl_id_count += 1 # need to update to keep ids unique
        newRule = self.ACL_ENTRY(ip_src=ip_src, ip_dst=ip_dst,
                                 tp_proto=tp_proto, port_src=port_src,
                                 port_dst=port_dst)
        self.access_control_list[rule_id] = newRule
        return (True, "Rule was created with id: " + rule_id + ".", newRule)
   
    """
    Remove a rule from the ACL then remove the associated flow table
    entries from the appropriate switches.
    
    @param rule_id - id of the rule to be removed.
    @return - a tuple indicating if the operation was a success and a
              message to be returned to the client.
    """
    def delete_acl_rule(self, rule_id):
        if rule_id not in self.access_control_list:
            return (False, "Invalid rule id given: " + rule_id + ".")
        # The user passed through a valid rule_id so we can proceed
        rule = self.access_control_list[rule_id]
        del self.access_control_list[rule_id]
        match = self.create_match(rule)
        for switch in self.connected_switches:
            datapath = api.get_datapath(self, switch)
            self.delete_flow(datapath, match)
        return (True, "Rule with id \'" + rule_id + "\' was deleted.")

    """
    Proactively distribute a newly added rule to all connected switches.
    It would seem intelligent to create the OFPMatch first then loop
    HOWEVER you cannot assume that switches will be running the same
    version of OpenFlow.
    
    @param rule - the ACL rule to distributed among the switches.
    """
    def distribute_single_rule(self, rule):
        for switch in self.connected_switches:
            datapath = api.get_datapath(self, switch)
            priority = self.OFP_MAX_PRIORITY
            actions = []
            match = self.create_match(rule)
            self.add_flow(datapath, priority, match, actions)

    """
    Proactively distribute hardcoded firewall rules to the switches.
    This function is called on application start-up to distribute rules
    read in from a file.
    
    @param datapath - an OF enabled switch to communicate with
    @param parser - parser for the switch passed through in datapath
    """
    def distribute_rules_switch_startup(self, datapath):
        for rule_id in self.access_control_list:
            rule = self.access_control_list[rule_id]
            priority = self.OFP_MAX_PRIORITY
            actions = []
            match = self.create_match(rule)
            self.add_flow(datapath, priority, match, actions)

    """
    Event handler used when a switch connects to the controller.
    """
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
        print ("[+] Switch connected with datapath id: " + str(ev.msg.datapath_id))
        # Take note of switches (via their datapaths)
        self.connected_switches.append(ev.msg.datapath_id)
        # Distribute the list of rules to the switch
        self.distribute_rules_switch_startup(datapath)

    """
    Delete a flow table entry from a switch. OFPFC_DELETE for flow removal
    over OFPFC_DELETE_STRICT. The later matches the flow, wildcards and
    priority which is not needed in this case.
    
    @param datapath - the switch to remove the flow table entry from.
    @param entry - the flow table entry to remove.
    """
    def delete_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        command = ofproto.OFPFC_DELETE
        mod = parser.OFPFlowMod(datapath=datapath, command=command,
                                match=match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)

    """
    Reactively add a flow table entry to a switch's flow table.
    """
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

    """
    Event handler used when a switch receives a packet that it cannot
    match a flow table entry with.
    """
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

# This class manages the RESTful API calls to add rules etc.
class ACLSwitchRESTInterface(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(ACLSwitchRESTInterface, self).__init__(req, link, data, **config)
        self.acl_switch_inst = data[acl_switch_instance_name]
   
    """
    API call to return the size of the ACl.
    """
    @route("acl_switch", url+"/acl", methods=["GET"])
    def return_acl_size(self, req, **kwargs):
        aclSize = {"acl_size":str(self.acl_switch_inst.acl_size())}
        body = json.dumps(aclSize)
        return Response(content_type="application/json", body=body)

    """
    API call to return the current contents of the ACL.
    """
    @route("acl_switch", url, methods=["GET"])
    def return_acl(self, req, **kwargs):
        acl = self.format_acl()
        body = json.dumps(acl)
        return Response(content_type="application/json", body=body)

    """
    API call to add a rule to the ACL.
    """
    @route("acl_switch", url, methods=["PUT"])
    def add_rule(self, req, **kwargs):
        try:
            ruleReq = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        if not self.check_rule_json(ruleReq):
            return Response(status=400, body="Invalid JSON passed.")
        result = self.acl_switch_inst.add_acl_Rule(ruleReq["ip_src"],
                                                    ruleReq["ip_dst"],
                                                    ruleReq["tp_proto"],
                                                    ruleReq["port_src"],
                                                    ruleReq["port_dst"])
        self.acl_switch_inst.distribute_single_rule(result[2])
        return Response(status=200, body=result[1])

    """
    API call to remove a rule from the ACL.
    """
    @route("acl_switch", url, methods=["DELETE"])
    def delete_rule(self, req, **kwargs):
        try:
            deleteReq = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        result = self.acl_switch_inst.delete_acl_rule(deleteReq["rule_id"])
        # rule doesn't exist send back HTTP 400
        if result[0] == True:
            status = 200
        else:
            status = 400
        return Response(status=status, body=result[1])

    """
    Turn the ACL into a dictionary for that it can be easily converted
    into JSON.
    
    @return - the acl formated in JSON.
    """
    def format_acl(self):
        acl_formatted = []
        for rule_id in self.acl_switch_inst.access_control_list:
            rule = self.acl_switch_inst.access_control_list[rule_id]
            # Order the list as it's created by using rule_id
            acl_formatted.insert(int(rule_id), {"rule_id":rule_id, "ip_src":rule.ip_src,
                                  "ip_dst":rule.ip_dst, "tp_proto":rule.tp_proto,
                                  "port_src": rule.port_src, "port_dst":rule.port_dst})
        return acl_formatted

    """
    Check that incoming JSON for an ACL has the required 5 fields:
    "ip_src", "ip_dst", "tp_proto", "port_src" and "port_dst".
    
    @param ruleJSON - input from the client to check.
    @return - True if ruleJSON is valid, False otherwise.
    """
    def check_rule_json(self, ruleJSON):
        if len(ruleJSON) != 5:
            return False
        if not "ip_src" in ruleJSON:
            return False
        if not "ip_dst" in ruleJSON:
            return False
        if not "tp_proto" in ruleJSON:
            return False
        if not "port_src" in ruleJSON:
            return False
        if not "port_dst" in ruleJSON:
            return False
        return True # everything is looking good!

