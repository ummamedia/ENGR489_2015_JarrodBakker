# A syntax checker for ACL rules. This is used by passing the appropriate
# values into the check_rule() function. The caller of check_rule() will
# be returned a list. If the list is empty then the rule is valid. However
# if the rule is not valid then the list will contain the appropriate error
# messages.
#
# Author: Jarrod N. Bakker
#

import socket, struct

# Check the ACL rule is valid.
# @param ip_src - the IP address to check
# @param ip_dst - the IP address to check
# @param tp_proto - the transport layer (layer 4) protocol to check
# @param port_src - the source port to check
# @param port_dst - the destination port to check
# @return - a list of the error messages. An empty list means that all
#           tests passed and the rule is valid.
def check_rule(ip_src, ip_dst, tp_proto, port_src, port_dst):
    errors = []
    if not check_ipv4(ip_src):
        errors.append("Invalid source IPv4 address: " + ip_src)
    if not check_ipv4(ip_dst):
        errors.append("Invalid destination IPv4 address: " + ip_dst)
    if not check_transport_protocol(tp_proto):
        errors.append("Invalid transport protocol (layer 4): " + tp_proto)
    if not check_port(port_src):
        errors.append("Invalid source port: " + port_src)
    if not check_port(port_dst):
        errors.append("Invalid destination port: " + port_dst)
    if not check_transport_valid(tp_proto, port_src, port_dst):
        errors.append("Unsupported rule: transport protocol: " + tp_proto +
                      " source port: " + port_src + " destination port: " +
                      port_dst)
    return errors

# Check that a valid IPv4 address has been specified.
# @param address - the IPv4 address to check
# @return - True if valid, False if not valid.
def check_ipv4(address):
    try:
        addr = struct.unpack("!I", socket.inet_aton(address))[0]
        return True
    except:
        if address == "*":
            return True
        return False

# ACLSwtich can block all traffic (denoted by tp_proto == "*") or by
# checking TCP or UDP port numbers. This function checks that the specified
# transport layer (layer 4) protocol is either "*", TCP or UDP.
# @param protocol - the transport layer (layer 4) protocol to check
# @return - True if valid, False if not valid.
def check_transport_protocol(protocol):
    return (protocol == "tcp" or protocol == "udp" or protocol == "*")

# A port is valid if it is either "*" or between 0 and 65535 inclusive
# @param port - the port number to check
# @return - True if valid, False if not valid.
def check_port(port):
    try:
        int(port)
        if int(port) < 0 or int(port) > 65535:
            return False
        return True
    except:
        if port == "*":
            return True
        return False

# An OFPMatch cannot have both TCP and UDP information in it. Therefore
# an ACL rule is not valid if the tp_proto is "*" and port numbers are
# specified.
# @param tp_proto - the transport layer (layer 4) protocol to check
# @param port_src - the source port to check
# @param port_dst - the destination port to check
# @return - True if valid, False if not valid.
def check_transport_valid(tp_proto, port_src, port_dst):
    return not(tp_proto == "*" and (port_src != "*" or port_dst != "*"))

if __name__ == "__main__":
    while(1):
        buf_in = raw_input("Rule: ")
        items = buf_in.split(" ")
        items[2] = items[2].lower()
        if len(items) != 5:
            print "Expected 5 arguments, " + str(len(items)) + " given."
            continue
        errors = check_rule(items[0], items[1], items[2], items[3], items[4])
        if len(errors) != 0 :
            print "Invalid rule provided:"
            for e in errors:
                print "\t" + e
            continue
        print items

