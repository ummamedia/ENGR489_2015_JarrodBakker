# An interactive command-line based interface for rule management of the
# Stateless SDN Firewall application. The interface
#
# The interface currently assumes that the user understands the syntax
# completely and does not check that input has been correctly provided.
#
# Author: Jarrod N. Bakker
#

# Libraries
import sys
import rule_syntax

# Constants
MODE_ADD = "ADD"
MODE_DELETE = "DELETE"
MODE_MAIN = "MAIN"
TEXT_ERROR_SYNTAX = "ERROR: Incorrect syntax, could not process given command."
TEXT_HELP_MAIN = "\tCommands: add, delete, show, help, quit"
TEXT_HELP_ADD = "\tRule to add: ip_src ip_dst transport_protocol port_src port_dst"
TEXT_HELP_DELETE = "\tRule to delete: rule_id"
PROMPT_MAIN = "ACL Switch > "
PROMPT_ADD = "ACL Switch (add) > "
PROMPT_DELETE = "ACL Switch (delete) > "

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
            # TODO display contents of the ACL
            print "TO BE IMPLEMENTED"
        elif result == "QUIT":
            sys.exit(0) 
        else:
            print result

# TODO add rule to the ACL
def interface_add():
    print TEXT_HELP_ADD
    result = text_input(MODE_ADD)
    # check that enough items were passed
    # check that addresses are valid e.g. valid IPv4 address or is '*'
    # check that transport protocol is valid: TCP, UDP or '*'
    # check that port numbers are valid e.g. port number is within valid range or is '*'
    print result

# TODO delete rule from the ACL
def interface_delete():
    print TEXT_HELP_DELETE
    result = text_input(MODE_DELETE)
    print result

# Evaluate the action based on the input given by the user
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

# Start the interface in a single thread
if __name__ == "__main__":
    interface_main()
