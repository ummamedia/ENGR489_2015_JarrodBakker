# An interactive command-line based interface for rule management of the
# Stateless SDN Firewall application.
#
# The interface will perform syntax checking on the input before sending
# it to ACLSwitch.
#
# Note that this application must be run on the controller itself.
#
# This file contains the logic for handling the assignment or removal of
# role to and from switches. This allows for much richer network security
# policy enforcement.
#
# Author: Jarrod N. Bakker
#

# Libraries
import json
import requests

class ACLInterfaceRole:

    # Constants
    PROMPT_ROLE = "ACL Switch (role) > "
    PROMPT_ROLE_ASSIGN = "ACL Switch (role -> assign) > "
    PROMPT_ROLE_CREATE = "ACL Switch (role -> create) > "
    PROMPT_ROLE_DELETE = "ACL Switch (role -> delete) > "
    PROMPT_ROLE_REMOVE = "ACL Switch (role -> remove) > "
    TEXT_ERROR_SYNTAX = "ERROR: Incorrect syntax, could not process given command."
    TEXT_ERROR_CONNECTION = "ERROR: Unable to establish a connection with ACLSwitch."
    TEXT_HELP_ROLE = "\tcreate, delete (role), assign OR remove (assignment)"
    TEXT_HELP_ROLE_ASSIGN = "\tRole to assign: switch_id role"
    TEXT_HELP_ROLE_CREATE = "\tRole to create: role"
    TEXT_HELP_ROLE_DELETE = "\tRole to delete: role"
    TEXT_HELP_ROLE_REMOVE = "\tRole to remove: switch_id role"
    URL_ACLSWITCH_ROLE = "http://127.0.0.1:8080/acl_switch/switch_roles" # using loopback
    
    """
    Assign interface. The user can assign or remove a role from a switch.
    This allows the switch to block different ranges of traffic compared
    to other switches within the network.
    """
    def __init__(self):
        print self.TEXT_HELP_ROLE
        buf_in = raw_input(self.PROMPT_ROLE)
        if buf_in == "create":
            self.role_create()
        elif buf_in == "delete":
            self.role_delete()
        elif buf_in == "assign":
            self.role_switch_assign()
        elif buf_in == "remove":
            self.role_switch_remove()
        else:
            print(self.TEXT_ERROR_SYNTAX + "\n" + self.TEXT_HELP_ROLE) # syntax error
    
    """
    Create a role.
    """
    def role_create(self):
        print self.TEXT_HELP_ROLE_CREATE
        role = raw_input(self.PROMPT_ROLE_CREATE)
        if " " in role:
            print("Role name cannot contain space character.")
            return
        create_req = json.dumps({"role":role})
        try:
            resp = requests.post(self.URL_ACLSWITCH_ROLE, data=create_req,
                                 headers={"Content-type":"application/json"})
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error modifying resource, HTTP " + str(resp.status_code))
        print resp.text

    """
    Delete a role.
    """
    def role_delete(self):
        print self.TEXT_HELP_ROLE_DELETE
        role = raw_input(self.PROMPT_ROLE_DELETE)
        if " " in role:
            print("Role name cannot contain space character.")
            return
        delete_req = json.dumps({"role":role})
        try:
            resp = requests.delete(self.URL_ACLSWITCH_ROLE, data=delete_req,
                                   headers={"Content-type":"application/json"})
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error modifying resource, HTTP " + str(resp.status_code))
        print resp.text

    """
    Assign a role to a switch.
    """
    def role_switch_assign(self):
        print self.TEXT_HELP_ROLE_ASSIGN
        buf_in = raw_input(self.PROMPT_ROLE_ASSIGN)
        new_assign = buf_in.split(" ")
        if len(new_assign) != 2:
            print("Expect 2 arguments, " + str(len(new_assign)) + " given.")
            return
        try:
            int(new_assign[0])
            if int(new_assign[0]) < 1:
                print "Switch id should be a positive integer greater than 1."
                return
        except:
            print "Switch id should be a positive integer greater than 1."
            return
        if new_assign[1] != "df" and new_assign[1] != "gw":
            print "Invalid role provided. \'df\' or \'gw\' expected."
            return
        assign_req = json.dumps({"switch_id":new_assign[0],
                                 "new_role":new_assign[1]})
        try:
            resp = requests.put(self.URL_ACLSWITCH_ROLE+"/assignment",
                                data=assign_req,
                                headers={"Content-type":"application/json"})
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error modifying resource, HTTP " + str(resp.status_code))
        print resp.text

    """
    Remove an assigned role from a switch.
    """
    def role_switch_remove(self):
        print self.TEXT_HELP_ROLE_REMOVE
        buf_in = raw_input(self.PROMPT_ROLE_REMOVE)
        removal = buf_in.split(" ")
        if len(removal) != 2:
            print("Expect 2 arguments, " + str(len(removal)) + " given.")
            return
        try:
            int(removal[0])
            if int(removal[0]) < 1:
                print "Switch id should be a positive integer greater than 1."
                return
        except:
            print "Switch id should be a positive integer greater than 1."
            return
        if removal[1] != "df" and removal[1] != "gw":
            print "Invalid role provided. \'df\' or \'gw\' expected."
            return
        remove_req = json.dumps({"switch_id":removal[0],
                                 "old_role":removal[1]})
        try:
            resp = requests.delete(self.URL_ACLSWITCH_ROLE+"/assignment",
                                   data=remove_req,
                                   headers = {"Content-type":"application/json"})
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error deleting resource, HTTP " + str(resp.status_code))
        print resp.text

