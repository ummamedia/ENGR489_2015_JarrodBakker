# An interactive command-line based interface for rule management of the
# Stateless SDN Firewall application. The interface
#
# The interface currently assumes that the user understands the syntax
# completely and does not check that input has been correctly provided.
#
# Author: Jarrod N. Bakker
#

# Libraries
import json
from prettytable import PrettyTable
import requests
import rule_syntax
import sys

# Constants
MODE_ADD = "ADD"
MODE_DELETE = "DELETE"
MODE_MAIN = "MAIN"
TEXT_ERROR_SYNTAX = "ERROR: Incorrect syntax, could not process given command."
TEXT_ERROR_CONNECTION = "ERROR: Unable to establish a connection with ACLSwitch."
TEXT_HELP_MAIN = "\tCommands: add, delete, show, help, quit"
TEXT_HELP_ADD = "\tRule to add: ip_src ip_dst transport_protocol port_src port_dst"
TEXT_HELP_DELETE = "\tRule to delete: rule_id"
PROMPT_MAIN = "ACL Switch > "
PROMPT_ADD = "ACL Switch (add) > "
PROMPT_DELETE = "ACL Switch (delete) > "
URL_ACL_SWITCH = ":8080/acl_switch"

# Return input from the user
# @param intMode - current mode of the interface e.g. add
# @return - the raw text input from the terminal
def text_input(intMode):
    if intMode == MODE_ADD:
        return raw_input(PROMPT_ADD)
    elif intMode == MODE_DELETE:
        return raw_input(PROMPT_DELETE)
    else:
        return raw_input(PROMPT_MAIN)

# Main interface. This is presented on start-up and after an operation
# has been processed.
def interface_main():
    while True:
        result = evaluate_input(text_input(MODE_MAIN))
        if result == "HELP":
            print TEXT_HELP_MAIN
        elif result == "ADD":
            interface_add()
        elif result == "DELETE":
            interface_delete()
        elif result == "SHOW":
            get_acl()
        elif result == "QUIT":
            sys.exit(0) 
        else:
            print result

# Evaluate the action based on the input given by the user. This is used
# by the interface when it is in 'main mode'.
# @param buf_in - input from the user
# @return buf_out - the output to be returned
def evaluate_input(buf_in):
    buf_proc = buf_in.split(" ") # the input to process
    buf_out = None
    if buf_proc[0] == "help":
        buf_out = "HELP"
    elif buf_proc[0] == "add":
        buf_out = "ADD"
    elif buf_proc[0] == "delete":
        buf_out = "DELETE"
    elif buf_proc[0] == "show":
        buf_out = "SHOW"
    elif buf_proc[0] == "quit":
        buf_out = "QUIT" # empty string needed as the tuple cannot have a length of 1
    else:
        buf_out = TEXT_ERROR_SYNTAX + "\n" + TEXT_HELP_MAIN # syntax error
    return buf_out

# Add interface. In this 'mode' the user is invited to input fields for an
# ACL rule. The rule is passed to ACLSwitch using a REST API as a JSON
# object.
def interface_add():
    print TEXT_HELP_ADD
    buf_in = text_input(MODE_ADD)
    items = buf_in.split(" ")
    if len(items) != 5:
        print "Expected 5 arguments, " + str(len(items)) + " given."
        return
    items[2] = items[2].lower()
    errors = rule_syntax.check_rule(items[0], items[1], items[2], items[3], items[4])
    if len(errors) != 0 :
        print "Invalid rule provided:"
        for e in errors:
            print "\t" + e
        return
    add_req = rule_to_json(items[0], items[1], items[2], items[3], items[4])
    try:
        resp = requests.put("http://127.0.0.1" + URL_ACL_SWITCH, data=add_req,
                            headers = {"Content-type": "application/json"})
    except:
        print TEXT_ERROR_CONNECTION
        return
    print resp.text

# Convert rule fields into a JSON object for transmission.
# @param ip_src - source IP address to be encoded
# @param ip_dst - destination IP address to be encoded
# @param tp_proto - transport layer (layer 4) protocol to be encoded
# @param port_src - source port number to be encoded
# @param port_dst - destination port number to be encoded
# @return - JSON representation of the rule
def rule_to_json(ip_src, ip_dst, tp_proto, port_src, port_dst):
   rule_dict = {}
   rule_dict["ip_src"] = ip_src
   rule_dict["ip_dst"] = ip_dst
   rule_dict["tp_proto"] = tp_proto
   rule_dict["port_src"] = port_src
   rule_dict["port_dst"] = port_dst
   return json.dumps(rule_dict)


# Delete interface. In this 'mode' the user is invited to input the ID of an
# ACL rule to be deleted. The ID is passed to ACLSwitch using a REST API as
# a JSON object.
def interface_delete():
    print TEXT_HELP_DELETE
    buf_in = text_input(MODE_DELETE)
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
        resp = requests.delete("http://127.0.0.1" + URL_ACL_SWITCH, data=delete_req,
                               headers = {"Content-type": "application/json"})
    except:
        print TEXT_ERROR_CONNECTION
        return
    print resp.text

# Fetch the current contents of the ACL and display it to the user. The ACL
# is requested using a REST API and should be returned as JSON.
def get_acl():
    print "Fetching ACL..."
    try:
        resp = requests.get("http://127.0.0.1" + URL_ACL_SWITCH)
    except:
        print TEXT_ERROR_CONNECTION
        return
    acl = resp.json()
    table = PrettyTable(["Rule ID", "Source Address", "Destination Address",
                         "Transport Protocol", "Source Port",
                         "Destination Port"])
    for rule in acl:
        table.add_row([rule["rule_id"], rule["ip_src"], rule["ip_dst"],
                       rule["tp_proto"], rule["port_src"], rule["port_dst"]])
    print table

# Start the interface.
if __name__ == "__main__":
    interface_main()
