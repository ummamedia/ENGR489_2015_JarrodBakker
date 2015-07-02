# An interactive command-line based interface for rule management of the
# Stateless Firewall (ACL) SDN application.
#
# The interface currently assumes that the user understands the syntax
# completely and does not check that input has been correctly provided.
#
# Author: Jarrod N. Bakker
#
#

import sys

# TODO have this running in another thread, started by acl_switch

TEXT_HELP = "To add a block rule:\n<-a or --add> <client address> <host address> <transport layer protocol> <source port> <destination port>"
TEXT_ERROR_SYNTAX = "ERROR: Incorrect syntax, could not process given command."
SIZE_ADD_RULE = 6 # number of items expected in user's input when they create a rule

# Return input from the user
def textInput():
    return raw_input()

# Evaluate the action based on the input given by the user
# @param buf_in - input from the user
# @return buf_out - the output to be returned
def evaluateInput(buf_in):
    buf_proc = buf_in.split(" ") # the input to process
    buf_out = None
    if buf_proc[0] == "-h" or buf_proc[0] == "--help":
        buf_out = TEXT_HELP
    elif (buf_proc[0] == "-a" or buf_proc[0] == "-add") and len(buf_proc) == SIZE_ADD_RULE:
        buf_out = buf_proc
        buf_out = ("ADD", buf_proc[1], buf_proc[2], buf_proc[3],
                   buf_proc[4],buf_proc[5])
    elif (buf_proc[0] == "-q" or buf_proc[0] == "--quit"):
        sys.exit(0)
    else:
        buf_out = TEXT_ERROR_SYNTAX + "\n" + TEXT_HELP
    return buf_out

# Main function for the interface
def main():
    print TEXT_HELP
    while True:
        result = evaluateInput(textInput())
        print result

if __name__ == "__main__":
    main()
