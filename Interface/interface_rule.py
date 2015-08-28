# An interactive command-line based interface for rule management of the
# Stateless SDN Firewall application.
#
# The interface will perform syntax checking on the input before sending
# it to ACLSwitch.
#
# Note that this application must be run on the controller itself.
#
# This file contains the logic for adding and removing rules from the ACL
# within ACLSwitch.
#
# Author: Jarrod N. Bakker
#

# Libraries
import json
import requests
import rule_syntax

class ACLInterfaceRule:

    # Constants
    PROMPT_RULE = "ACL Switch (rule) > "
    PROMPT_RULE_ADD = "ACL Switch (rule -> add) > "
    PROMPT_RULE_REMOVE = "ACL Switch (rule -> remove) > "
    TEXT_ERROR_SYNTAX = "ERROR: Incorrect syntax, could not process given command."
    TEXT_ERROR_CONNECTION = "ERROR: Unable to establish a connection with ACLSwitch."
    TEXT_HELP_RULE = "\tadd OR remove"
    TEXT_HELP_RULE_ADD = "\tRule to add: ip_src ip_dst transport_protocol port_src port_dst role"
    TEXT_HELP_RULE_REMOVE = "\tRule to remove: rule_id"
    URL_ACLSWITCH_RULE = "http://127.0.0.1:8080/acl_switch/acl_rules" # using loopback

    """
    Add interface. In this 'mode' the user is invited to input fields for an
    ACL rule. The rule is passed to ACLSwitch using a REST API as a JSON
    object.
    """
    def __init__(self):
        print self.TEXT_HELP_RULE
        buf_in = raw_input(self.PROMPT_RULE)
        if buf_in == "add":
            self.rule_add()
        elif buf_in == "remove":
            self.rule_remove()
        else:
            print(self.TEXT_ERROR_SYNTAX + "\n" + self.TEXT_HELP_RULE) # syntax error
            
    """
    Convert rule fields into a JSON object for transmission.
    
    @param ip_src - source IP address to be encoded
    @param ip_dst - destination IP address to be encoded
    @param tp_proto - transport layer (layer 4) protocol to be encoded
    @param port_src - source port number to be encoded
    @param port_dst - destination port number to be encoded
    @return - JSON representation of the rule
    """
    def rule_to_json(self, ip_src, ip_dst, tp_proto, port_src, port_dst, role):
       rule_dict = {}
       rule_dict["ip_src"] = ip_src
       rule_dict["ip_dst"] = ip_dst
       rule_dict["tp_proto"] = tp_proto
       rule_dict["port_src"] = port_src
       rule_dict["port_dst"] = port_dst
       rule_dict["role"] = role
       return json.dumps(rule_dict)

    """
    The user is invited to input fields for an ACL rule. The rule is
    passed to ACLSwitch using a REST API as a JSON object.
    """
    def rule_add(self):
        print self.TEXT_HELP_RULE_ADD
        buf_in = raw_input(self.PROMPT_RULE_ADD)
        items = buf_in.split(" ")
        if len(items) != 6:
            print "Expected 6 arguments, " + str(len(items)) + " given."
            return
        items[2] = items[2].lower()
        errors = rule_syntax.check_rule(items[0], items[1], items[2],
                                        items[3], items[4], items[5])
        if len(errors) != 0 :
            print "Invalid rule provided:"
            for e in errors:
                print "\t" + e
            return
        add_req = self.rule_to_json(items[0], items[1], items[2],
                                    items[3], items[4], items[5])
        try:
            resp = requests.post(self.URL_ACLSWITCH_RULE, data=add_req,
                                headers = {"Content-type": "application/json"})
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error creating resource, HTTP " + str(resp.status_code))
        print resp.text



    """
    The user is invited to input the ID of an ACL rule to be deleted.
    The ID is passed to ACLSwitch using a REST API as a JSON object.
    """
    def rule_remove(self):
        print self.TEXT_HELP_RULE_REMOVE
        buf_in = raw_input(self.PROMPT_RULE_REMOVE)
        try:
            int(buf_in)
            if int(buf_in) < 0:
                print "Rule id should be a positive integer."
                return
        except:
            print "Rule id should be a positive integer."
            return
        delete_req = json.dumps({"rule_id": buf_in})
        try:
            resp = requests.delete(self.URL_ACLSWITCH_RULE, data=delete_req,
                                   headers = {"Content-type": "application/json"})
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error deleting resource, HTTP " + str(resp.status_code))
        print resp.text

