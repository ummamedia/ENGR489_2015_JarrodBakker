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
import interface_role
import interface_rule
import interface_show
import sys

class ACLInterfaceMain:

    # Constants
    PROMPT_MAIN = "ACL Switch > "
    TEXT_ERROR_SYNTAX = "ERROR: Incorrect syntax, could not process given command."
    TEXT_ERROR_CONNECTION = "ERROR: Unable to establish a connection with ACLSwitch."
    TEXT_HELP_MAIN = "\tCommands: role, rule, show, help, quit"

    def __init__(self):
        while True:
            buf_in = raw_input(self.PROMPT_MAIN)
            if buf_in == "role":
                interface_role.ACLInterfaceRole()
            elif buf_in == "rule":
                interface_rule.ACLInterfaceRule()
            elif buf_in == "show":
                interface_show.ACLInterfaceShow()
            elif buf_in == "quit":
                print("Closing interface...")
                sys.exit(0)
            else:
                print(self.TEXT_ERROR_SYNTAX + "\n" + self.TEXT_HELP_MAIN) # syntax error

"""
Start the interface.
"""
if __name__ == "__main__":
    ACLInterfaceMain()

