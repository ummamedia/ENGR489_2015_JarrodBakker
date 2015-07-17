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
from ryu.lib.packet import tcp
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
    ACL_ENTRY = namedtuple("ACL_ENTRY", "ip_src ip_dst tp_proto port_src port_dst ofp13_match")
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

    # Read in ACL rules from file filename. Note that the values passed
    # through will have 'u' in front of them. This denotes that the string
    # is Unicode encoded, as such it will affect the intended value.
    # @param filename - the input file
    # TODO handle case where file cannot be found
    def import_from_file(self, filename):
        buf_in = open(filename)
        for line in buf_in:
            if line[0] == "#":
                continue # Skip file comments
            rule = json.loads(line)
            self.add_acl_Rule(rule["ip_src"], rule["ip_dst"],
                              rule["tp_proto"], rule["port_src"],
                              rule["port_dst"])
    
    # Return the size of the ACL.
    # @return - the size of the ACL
    def acl_size(self):
        return len(self.access_control_list)

    # Add a rule to the ACL by creating an entry then appending it to the list. 
    # @param ip_src - the source IP address to match
    # @param ip_dst - the destination IP address to match
    # @param tp_proto - the Transport Layer (layer 4) protocol to match
    # @param port_src - the Transport Layer source port to match
    # @param port_dst - the Transport Layer destination port to match
    # @return - the newly created rule. This is useful in the case where a
    #           single rule has been created and needs to be distributed.
    def add_acl_Rule(self, ip_src, ip_dst, tp_proto, port_src, port_dst):
        match = ofp13_parser.OFPMatch()
        match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,
                           ethernet.ether.ETH_TYPE_IP)
        if (ip_src != "*"):
            match.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC,
                               struct.unpack("!I", socket.inet_aton(ip_src))[0])
        if (ip_dst != "*"):
            match.append_field(ofproto_v1_3.OXM_OF_IPV4_DST,
                               struct.unpack("!I", socket.inet_aton(ip_dst))[0])
        if (tp_proto != "*"):
            if (tp_proto == "tcp"):
                match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                   ipv4.inet.IPPROTO_TCP)
                if (port_src != "*"):
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_SRC,
                                       int(port_src))
                if (port_src != "*"):
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_DST,
                                       int(port_dst))
            elif (tp_proto == "udp"):
                match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                   ipv4.inet.IPPROTO_UDP)
                if (port_src != "*"):
                    match.append_field(ofproto_v1_3.OXM_OF_UDP_SRC,
                                       int(port_src))
                if (port_src != "*"):
                    match.append_field(ofproto_v1_3.OXM_OF_UDP_DST,
                                       int(port_dst))
        rule_id = self.acl_id_count
        self.acl_id_count += 1 # need to update to keep ids unique
        newRule = self.ACL_ENTRY(ip_src=ip_src, ip_dst=ip_dst,
                                 tp_proto=tp_proto, port_src=port_src,
                                 port_dst=port_dst, ofp13_match=match)
        self.access_control_list[str(rule_id)] = newRule
        return newRule
   
    # Remove a rule from the ACL then remove the associated flow table
    # entries from the appropriate switches.
    # @param rule_id - id of the rule to be removed.
    # @return - true if the operation was successful, false otherwise.
    def delete_acl_rule(self, rule_id):
    # TODO switch the ACL storage from a list to a dict (k=id,v=entry) and remove the id field from an ACL_ENTRY. O(1) traversal is always nice. the acl_if_count field will make keeping track of the ids easy as well. Will also need to change the format_acl() function for the REST interface as well as a list will no longer being sent back once this change has been made.
        if rule_id not in self.access_control_list:
            return False
        rule = self.access_control_list[rule_id]
        del self.access_control_list[rule_id]
        # remove rule from switches using entry
        for switch in self.connected_switches:
            datapath = api.get_datapath(self, switch)
            self.delete_flow(datapath, rule.ofp13_match)

    # Proactively distribute a newly added rule to all connected switches.
    # It would seem intelligent to create the OFPMatch first then loop
    # HOWEVER you cannot assume that switches will be running the same
    # version of OpenFlow.
    # @param rule - the ACL rule to distributed among the switches.
    def distribute_single_rule(self, rule):
        for switch in self.connected_switches:
            datapath = api.get_datapath(self, switch)
            priority = self.OFP_MAX_PRIORITY
            actions = []
            self.add_flow(datapath, priority, rule.ofp13_match, actions)

    # Proactively distribute hardcoded firewall rules to the switches.
    # This function is called on application start-up to distribute rules
    # read in from a file.
    # @param datapath - an OF enabled switch to communicate with
    # @param parser - parser for the switch passed through in datapath
    def distribute_rules_switch_startup(self, datapath):
        for rule_id in self.access_control_list:
            rule = self.access_control_list[rule_id]
            priority = self.OFP_MAX_PRIORITY
            actions = []
            self.add_flow(datapath, priority, rule.ofp13_match, actions)

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
        self.distribute_rules_switch_startup(datapath)

    # Delete a flow table entry from a switch.
    # @param datapath - the switch to remove the flow table entry from.
    # @param entry - the flow table entry to remove.
    def delete_flow(self, datapath, entry):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # compile the instructions
        # compile the flow mod message
        # datapath.send_msg(mod)

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

# This class manages the RESTful API calls to add rules etc.
class ACLSwitchRESTInterface(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(ACLSwitchRESTInterface, self).__init__(req, link, data, **config)
        self.acl_switch_inst = data[acl_switch_instance_name]
   
    # API call to return the size of the ACl.
    # example curl -X GET http://127.0.0.1:8080/acl_switch/acl
    @route("acl_switch", url+"/acl", methods=["GET"])
    def return_acl_size(self, req, **kwargs):
        aclSize = {"acl_size":str(self.acl_switch_inst.acl_size())}
        body = json.dumps(aclSize)
        return Response(content_type="application/json", body=body)

    # API call to return the current contents of the ACL.
    # example: curl -X GET http://127.0.0.1:8080/acl_switch
    @route("acl_switch", url, methods=["GET"])
    def return_acl(self, req, **kwargs):
        acl = self.format_acl()
        body = json.dumps(acl)
        return Response(content_type="application/json", body=body)

    # API call to add a rule to the ACL.
    # example: curl -X PUT -d '{"ip_src":"10.0.0.2", "ip_dst":"10.0.0.3", "tp_proto":"*", "port_src":"*", "port_dst":"*"}' http://127.0.0.1:8080/acl_switch
    @route("acl_switch", url, methods=["PUT"])
    def add_rule(self, req, **kwargs):
        ruleReq = json.loads(req.body)
        newRule = self.acl_switch_inst.add_acl_Rule(ruleReq["ip_src"],
                                                    ruleReq["ip_dst"],
                                                    ruleReq["tp_proto"],
                                                    ruleReq["port_src"],
                                                    ruleReq["port_dst"])
        self.acl_switch_inst.distribute_single_rule(newRule)
        # TODO return response indicating success

    # API call to remove a rule from the ACL.
    # example: curl -X DELETE -d '{"rule_id":"0"}' http://127.0.0.1:8080/acl_switch
    @route("acl_switch", url, methods=["DELETE"])
    def delete_rule(self, req, **kwargs):
        print "[+] Removing rule from ACL."
        # TODO return response indicating succes
        deleteReq = json.loads(req.body)
        result = self.acl_switch_inst.delete_acl_rule(deleteReq["rule_id"])

    # Turn the ACL into a dictionary for that it can be easily converted
    # into JSON. The ofp13_match value does not need to be sent as this is
    # information that only the controller should worry about.
    # @return - 
    def format_acl(self):
        acl_formatted = []
        for rule_id in self.acl_switch_inst.access_control_list:
            rule = self.acl_switch_inst.access_control_list[rule_id]
            # Order the list as it's created by using rule_id
            acl_formatted.insert(int(rule_id), {"rule_id":rule_id, "ip_src":rule.ip_src,
                                  "ip_dst":rule.ip_dst, "tp_proto":rule.tp_proto,
                                  "port_src": rule.port_src, "port_dst":rule.port_dst})
        return acl_formatted

