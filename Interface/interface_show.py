# An interactive command-line based interface for rule management of the
# Stateless SDN Firewall application.
#
# The interface will perform syntax checking on the input before sending
# it to ACLSwitch.
#
# Note that this application must be run on the controller itself.
#
# This file contains the logic for starting the interface program and
# directing control to other interface functions.
#
# Author: Jarrod N. Bakker
#

# Libraries
import json
from prettytable import PrettyTable
import requests

class ACLInterfaceShow:

    # Constants
    PROMPT_SHOW = "ACL Switch (show) > "
    TEXT_ERROR_SYNTAX = "ERROR: Incorrect syntax, could not process given command."
    TEXT_ERROR_CONNECTION = "ERROR: Unable to establish a connection with ACLSwitch."
    TEXT_HELP_SHOW = "\tacl OR switch"
    URL_ACLSWITCH_ROLE = "http://127.0.0.1:8080/acl_switch/switch_roles" # using loopback
    URL_ACLSWITCH_RULE = "http://127.0.0.1:8080/acl_switch/acl_rules" # using loopback

    """
    Show interface. The user has the option to either view the contents of the
    ACL or view the currently connected switches and the roles associated with
    each one.
    """
    def __init__(self):
        print self.TEXT_HELP_SHOW
        buf_in = raw_input(self.PROMPT_SHOW)
        if buf_in == "acl":
            self.get_acl()
        elif buf_in == "switch":
            self.get_switches()
        else:
            print(self.TEXT_ERROR_SYNTAX + "\n" + self.TEXT_HELP_SHOW) # syntax error

    """
    Fetch the current contents of the ACL and display it to the user.
    The ACL is requested using a REST API and should be returned as JSON.
    """
    def get_acl(self):
        print("Fetching ACL...")
        try:
            resp = requests.get(self.URL_ACLSWITCH_RULE)
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error fetching resource, HTTP " + str(resp.status_code)
                  + " returned.")
            return
        acl = resp.json()
        table = PrettyTable(["Rule ID", "Source Address", "Destination Address",
                             "Transport Protocol", "Source Port",
                             "Destination Port", "Role"])
        for rule in acl:
            table.add_row([rule["rule_id"], rule["ip_src"], rule["ip_dst"],
                           rule["tp_proto"], rule["port_src"], rule["port_dst"],
                           rule["role"]])
        print table

    """
    Fetch a list of the current switches and the roles associated with
    them from the ACLSwitch.
    """
    def get_switches(self):
        print("Fetching switch information...")
        try:
            resp = requests.get(self.URL_ACLSWITCH_ROLE)
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error fetching resource, HTTP " + str(resp.status_code)
                  + " returned.")
            return
        switches = resp.json()
        table = PrettyTable(["Switch Datapath ID", "Roles"])
        for entry in switches:
            table.add_row([entry, switches[entry]])
        print table

