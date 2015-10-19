# Copyright 2015 Jarrod N. Bakker
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###########################################################################
# Author: Jarrod N. Bakker
# Part of an ENGR489 project at Victoria University of Wellington
# during 2015.
#
# This implementation of ACLSwitch enforces stateless firewall policies
# by looking at the source and destination IP addresses,
# the transport-layer protocol and source and destination ports.
# Different sets of rules can be distributed to switches uses roles. As
# a result, rich policies can be deployed on top of a network topology.
# A rule within the ACL indicates a flow of traffic that should be
# blocked at the switches.
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

# Modules
# Ryu and OpenFlow protocol
from ryu.app.ofctl import api
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as ofp13_parser

# Packets
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from netaddr import IPAddress

# REST interface
from ryu.app.wsgi import WSGIApplication
from ryu.ENGR489_2015_JarrodBakker.ACLSwitch import acl_switch_rest_interface

# Other
from collections import namedtuple
from datetime import datetime
import json
import signal
import sys

# Global field needed for REST linkage
acl_switch_instance_name = "acl_switch_app"

class ACLSwitch(app_manager.RyuApp):
    # Constants
    ACL_ENTRY = namedtuple("ACL_ENTRY", "ip_src ip_dst tp_proto port_src port_dst role")
        # Contains the connection 5-tuple and the OFPMatch instance for OF 1.3
    ACL_FILENAME = "ryu/ENGR489_2015_JarrodBakker/ACLSwitch/config.json"
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    OFP_MAX_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY*2 - 1
        # Default priority is defined to be in the middle (0x8000 in 1.3)
        # Note that for a priority p, 0 <= p <= MAX (i.e. 65535)
    ROLE_DEFAULT = "df"

    _CONTEXTS = {"wsgi":WSGIApplication}

    # Fields
    access_control_list = {} # rule_id:ACL_ENTRY # This is the master list
    acl_id_count = 0
    connected_switches = {} # dpip:[roles]
    role_to_rules = {} # role:[rules]

    def __init__(self, *args, **kwargs):
        super(ACLSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        # Start empty lists for the dict value
        self.role_to_rules[self.ROLE_DEFAULT] = []

        # Import config from file
        try:
            self.import_from_file(self.ACL_FILENAME)
        except:
            print("[-] ERROR: could not read from file \'"
                  + str(self.ACL_FILENAME) + "\'\n\t"
                  + str(sys.exc_info()))
        
        # Create an object for the REST interface
        wsgi = kwargs['wsgi']
        wsgi.register(acl_switch_rest_interface.ACLSwitchRESTInterface, {acl_switch_instance_name : self})

    """
    Read in ACL rules from file filename. Note that the values passed
    through will have 'u' in front of them. This denotes that the string
    is Unicode encoded, as such it will affect the intended value.

    @param filename - the input file
    """
    def import_from_file(self, filename):
        buf_in = open(filename)
        print("[?] Reading from file \'" + str(filename) + "\'")
        for line in buf_in:
            if line[0] == "#" or not line.strip():
                continue # Skip file comments and empty lines
            try:
               config = json.loads(line)
            except:
                print("[-] Line: " + line + "is not valid JSON.")
                continue
            if "rule" in config:
                self.add_acl_Rule(config["rule"]["ip_src"],
                                  config["rule"]["ip_dst"],
                                  config["rule"]["tp_proto"],
                                  config["rule"]["port_src"],
                                  config["rule"]["port_dst"],
                                  config["rule"]["role"])
            elif "role" in config:
                self.role_create(config["role"])
            else:
                print("[-] Line: " + line + "is not recognised JSON.")
   
    """
    Compile and return information on ACLSwitch. The information is
    comprised of the number of roles, the number of ACL rules, the
    number of switches and the current time of the machine that this
    application is running on. This should only be taken as an
    approximation of the current time therefore the time should only
    be accurate within minutes.

    @return - a dictionary containing information on the ACLSwitch.
    """
    def get_info(self):
        num_roles = str(len(self.role_to_rules))
        num_rules = str(len(self.access_control_list))
        num_switches = str(len(self.connected_switches))
        current_time = datetime.now()
        if int(current_time.minute) > 9:
            controller_time = (str(current_time.hour) + ":"
                               + str(current_time.minute))
        else:
            controller_time = (str(current_time.hour) + ":0"
                               + str(current_time.minute))
        return {"num_roles":num_roles, "num_rules":num_rules,
                "num_switches":num_switches,
                "controller_time":controller_time}

    # Functions handling the management of switch roles

    """
    List the currently available roles.

    @return - a list of the currently available roles.
    """
    def role_list(self):
        return self.role_to_rules.keys()

    """
    Create a role which can then be assigned to a switch.

    @param new_role - the role to create.
    @return - result of the operation along with a message.
    """
    def role_create(self, new_role):
        if new_role in self.role_to_rules:
            return (False, "Role " + new_role + " already exists.")
        self.role_to_rules[new_role] = []
        print("[+] New role added: " + new_role)
        return (True, "Role " + new_role + " created.")

    """
    Delete a role. This can only be done once there are no rules
    associated with the role.

    @param role - the role to delete.
    @return - result of the operation along with a message.
    """
    def role_delete(self, role):
        if role == self.ROLE_DEFAULT:
            return (False, "Role df cannot be deleted.")
        if role not in self.role_to_rules:
            return (False, "Role " + role + " does not exist.")
        if self.role_to_rules[role]:
            return (False, "Cannot delete role " + role +
                    ", rules are still assoicated with it.")
        for switch in self.connected_switches:
            if role in self.connected_switches[switch]:
                return (False, "Cannot delete role " + role +
                        ", switches still have it assigned.")
        del self.role_to_rules[role]
        print("[+] Role deleted: " + role)
        return (True, "Role " + role + " deleted.")

    """
    Assign a role to a switch then give it the appropriate rules.

    @param switch_id - the datapath_id of a switch, switch_id is used
                       for consistency with the API.
    @param role - the new role to assign to a switch.
    @return - result of the operation along with a message.
    """
    def switch_role_assign(self, switch_id, new_role):
        if new_role not in self.role_to_rules:
            return (False, "Role " + new_role + " does not exist.")
        if switch_id not in self.connected_switches:
            return (False, "Switch " + str(switch_id) + " does not exist.")
        if new_role in self.connected_switches[switch_id]:
            return (False, "Switch " + str(switch_id) + " already has role "
                    + str(new_role) + ".")
        self.connected_switches[switch_id].append(new_role)
        datapath = api.get_datapath(self, switch_id)
        self.distribute_rules_role_set(datapath, new_role)
        print("[+] Switch " + str(switch_id) + " assigned role: " + new_role)
        return (True, "Switch " + str(switch_id) + " given role "
                + new_role + ".")

    """
    Remove a role assignment from a switch then remove the respective
    rules from the switch. Assumes that once the role has been removed
    the respective rules will be successfully removed from the switches.

    @param switch_id - the datapath_id of a switch, switch_id is used
                       for consistency with the API.
    @param old_role - the role to remove from a switch.
    @return - result of the operation along with a message.
    """
    def switch_role_remove(self, switch_id, old_role):
        if old_role not in self.role_to_rules:
            return (False, "Role " + old_role + " does not exist.")
        if switch_id not in self.connected_switches:
            return (False, "Switch " + str(switch_id) + " does not exist.")
        if old_role not in self.connected_switches[switch_id]:
            return (False, "Switch " + str(switch_id) + " does not have role "
                    + str(old_role) + ".")
        self.connected_switches[switch_id].remove(old_role)
        datapath = api.get_datapath(self, switch_id)
        for rule_id in self.role_to_rules[old_role]:
            rule = self.access_control_list[rule_id]
            match = self.create_match(rule)
            self.delete_flow(datapath, self.OFP_MAX_PRIORITY, match)
        print("[+] Switch " + str(switch_id) + " removed role: " + old_role)
        return (True, "Switch " + str(switch_id) + " had role "
                + old_role + " removed.")

    # Functions handling the use of the ACL

    """
    Return the size of the ACL.

    @return - the size of the ACL
    """
    def acl_size(self):
        return len(self.access_control_list)

    """
    Return the IP version being used given the source and destination
    addresses. 

    @param ip_src - the source IP address to check. 
    @param ip_dst - the destination IP address to check.
    @return - the IP version being used.
    """
    def return_ip_version(self, ip_src, ip_dst):
        if "*" not in ip_src:
            return IPAddress(ip_src).version
        else:
            return IPAddress(ip_dst).version

    """
    Create an OFPMatch instance based on the contents of an ACL_ENTRY.

    @param rule - the entry to create an OFPMatch instance from
    @return - the OFPMatch instance
    """
    def create_match(self, rule):
        match = ofp13_parser.OFPMatch()
        ip_version = self.return_ip_version(rule.ip_src, rule.ip_dst)
        # Match IP layer (layer 3)
        if ip_version == 4:
            # Match IPv4
            match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,
                               ethernet.ether.ETH_TYPE_IP)
            if rule.ip_src != "*":
                match.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC,
                                    int(IPAddress(rule.ip_src)))
            if rule.ip_dst != "*":
                match.append_field(ofproto_v1_3.OXM_OF_IPV4_DST,
                                   int(IPAddress(rule.ip_dst)))
        else:
            # Match IPv6
            match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,
                               ethernet.ether.ETH_TYPE_IPV6)
            if rule.ip_src != "*":
                match.append_field(ofproto_v1_3.OXM_OF_IPV6_SRC,
                                   IPAddress(rule.ip_src).words)
            if rule.ip_dst != "*":
                match.append_field(ofproto_v1_3.OXM_OF_IPV6_DST,
                                   IPAddress(rule.ip_dst).words)

        # Match transport layer (layer 4) 
        if rule.tp_proto != "*":
            if rule.tp_proto == "tcp":
                # Match TCP
                match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                   ipv4.inet.IPPROTO_TCP) # covers IPv6
                if rule.port_src != "*":
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_SRC,
                                       int(rule.port_src))
                if rule.port_dst != "*":
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_DST,
                                       int(rule.port_dst))
            elif rule.tp_proto == "udp":
                # Match UDP
                match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                   ipv4.inet.IPPROTO_UDP) # covers IPv6
                if rule.port_src != "*":
                    match.append_field(ofproto_v1_3.OXM_OF_UDP_SRC,
                                       int(rule.port_src))
                if rule.port_dst != "*":
                    match.append_field(ofproto_v1_3.OXM_OF_UDP_DST,
                                       int(rule.port_dst))
        return match

    """
    Returns a string representation of an IP address.

    @param ip_addr - the IP address to turn into a string.
    @return - the string representation of an IP address.
    """
    def ip_to_string(self, ip_addr):
        if ip_addr == "*":
            return ip_addr
        return str(IPAddress(ip_addr))

    """
    Compare the 5-tuple entries of two ACL rules. That is compare the
    IP addresses, transport-layer protocol and port numbers.
    """
    def compare_acl_rules(self, rule_1, rule_2):
        return ((self.ip_to_string(rule_1.ip_src)==self.ip_to_string(rule_2.ip_src)) and
                (self.ip_to_string(rule_1.ip_dst)==self.ip_to_string(rule_2.ip_dst)) and
                (rule_1.tp_proto==rule_2.tp_proto) and
                (rule_1.port_src==rule_2.port_src) and
                (rule_1.port_dst==rule_2.port_dst))

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
    def add_acl_Rule(self, ip_src, ip_dst, tp_proto, port_src, port_dst, role):
        if role not in self.role_to_rules:
            return (False, "Role " + role + " was not recognised.", None)
        rule_id = str(self.acl_id_count)
        self.acl_id_count += 1 # need to update to keep ids unique
        new_rule = self.ACL_ENTRY(ip_src=ip_src, ip_dst=ip_dst,
                                 tp_proto=tp_proto, port_src=port_src,
                                 port_dst=port_dst, role=role)
        for rule in self.access_control_list.values():
            if self.compare_acl_rules(new_rule, rule):
                return (False, "New rule was not created, it already "
                        "exists.", None)
        self.access_control_list[rule_id] = new_rule
        self.role_to_rules[role].append(rule_id)
        print("[+] Rule " + str(new_rule) + " created with id: "
              + str(rule_id))
        return (True, "Rule was created with id: " + str(rule_id) + ".", new_rule)
   
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
        self.role_to_rules[rule.role].remove(rule_id)
        for switch in self.connected_switches:
            if rule.role not in self.connected_switches[switch]:
                continue
            match = self.create_match(rule)
            datapath = api.get_datapath(self, switch)
            self.delete_flow(datapath, self.OFP_MAX_PRIORITY, match)
        print("[+] Rule " + str(rule) + " with id: " + str(rule_id)
              + " removed.")
        return (True, "Rule with id \'" + rule_id + "\' was deleted.")

    # Functions handling ACL rule distribution

    """
    Proactively distribute a newly added rule to all connected switches.
    It is necessary to check the a switch is not given a rule for which
    it is not allowed to have. This is done by comparing roles.
    
    Called when a rule has been created.
    
    @param rule - the ACL rule to distributed among the switches.
    """
    def distribute_single_rule(self, rule):
        for switch in self.connected_switches:
            switch_roles = self.connected_switches[switch]
            if rule.role not in switch_roles:
                continue
            datapath = api.get_datapath(self, switch)
            priority = self.OFP_MAX_PRIORITY
            actions = []
            match = self.create_match(rule)
            self.add_flow(datapath, priority, match, actions)

    """
    Proactively distribute hardcoded firewall rules to the switch
    specified using the datapath. Distribute the rules associated
    with the role provided.
    
    Called when a switch is assigned a role.
    
    @param datapath - an OF enabled switch to communicate with
    @param role - the role of the switch
    """
    def distribute_rules_role_set(self, datapath, role):
        for rule_id in self.role_to_rules[role]:
            rule = self.access_control_list[rule_id]
            priority = self.OFP_MAX_PRIORITY
            actions = []
            match = self.create_match(rule)
            self.add_flow(datapath, priority, match, actions)

    # Functions handling OpenFlow flow table entries
    
    """
    Delete a flow table entry from a switch. OFPFC_DELETE_STRICT is used
    as you only want to remove exact matches of the rule. 
    
    @param datapath - the switch to remove the flow table entry from.
    @param priority - priority of the rule to remove.
    @param match - the flow table entry to remove.
    """
    def delete_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        command = ofproto.OFPFC_DELETE_STRICT
        mod = parser.OFPFlowMod(datapath=datapath, command=command,
                                priority=priority, match=match,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)

    """
    Reactively add a flow table entry to a switch's flow table.

    @param datapath - the switch to add the flow table entry to.
    @param time_limit - when the rule should expire.
    @param priority - priority of the rule to add.
    @param match - the flow table entry to add.
    @param actions - action for a switch to perform.
    @param buffer_id - identifier of buffer queue if traffic is being
                       buffered.
    """
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority, match=match,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    instructions=inst)
        datapath.send_msg(mod)

    # Functions handling OpenFlow events
    
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
        # Take note of switches (via their datapaths)
        dp_id = ev.msg.datapath_id
        self.connected_switches[dp_id] = [self.ROLE_DEFAULT]

        print("[?] Switch " + str(dp_id) + " connected.")

        # Distribute the list of rules to the switch
        self.distribute_rules_role_set(datapath, self.ROLE_DEFAULT)

    """
    Event handler used when a flow table entry is deleted.
    """
    @set_ev_cls(ofp_event.EventOFPFlowRemoved)
    def rule_deletion_handler(self, ev):
        msg = ev.msg
        match = msg.match
        print("[?] Flow table entry removed.\n\t Flow match: "
              + str(match))

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
            
            print "[?] New flow: " + str(pkt)
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

