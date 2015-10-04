#!/usr/bin/env python

#
# Test: Verify that IPv6 traffic gets blocked when it originates from
#       host 1. As TCP and UDP packets do not receive replies were on
#       top of IPv6 and sent using Scapy, ICMPv6 Echo Requests will be
#       used to test the lack of connectivity. Care must be taken that
#       this test is run on host 1 with an IPv6 address of
#       fe80::200:ff:fe00:1. The ACL rules can be found in 
#       DropSelectH1_IPv6TCP_destPort_rules.json
#
# Usage: python DropSelectH1_IPv6TCP_destPort.py <number of hosts in the network>
#
# Test success: All traffic receives some form of response (dependent 
#               on protocol).
# Test failure: At least one flow does not received an answer.
#
# Note:
#   - Test output can be found in DropSelectH1_IPv6TCP_destPort_results.log
#
#   - To perform a port scan of TCP destination ports, Paramiko was used.
#     It is a SSH module for Python.
#
#   - The script assumes that the host is part of the 10.0.0.0/24
#     subnet.
#
#   - The script assumes that the syntax for the REST commands are
#     legal.
#
# Author: Jarrod N. Bakker
#

from time import sleep
import json
import logging
import netifaces as ni
import os
import paramiko
import requests
import socket
import sys

FILENAME_LOG_RESULTS = None
HOST1_INTERFACE = "%h1-eth0"
NETWORK_IPV6 = "fe80::200:ff:fe00:"
PORT_NUM_DST = [20,21,22,23,80,123,194,1000,1001,1002,1003,1004,2000,2001,2002,2003,2004,6633,8080,8333]
TEST_SCRIPT_ARGS = "<number of hosts in the network>"
TEST_NAME = None
TIMEOUT = 1
TIME_SLEEP = 1

"""
 Fetch and return the IPv6 address of THIS host from interface h#_eth0
 where # is the host number.
 @return - the IPv6 address of the host's h#_eth0 interface
"""
def get_host_ipv6():
    all_ifaces = ni.interfaces()
    host_iface = None
    for iface in all_ifaces:
        if "eth0" in iface:
            host_iface = iface
            break 
    if host_iface == None:
        print logging.critical("Unable to find an interface ending with"
                               " \'eth0\'")
        sys.exit(1)
    # Get the hosts IPv6 Link local address (it will do) and strip
    # off the interface information.
    host_ipv6 = ni.ifaddresses(host_iface)[ni.AF_INET6][0]["addr"][:-8]
    return host_ipv6

"""
 Create the list of IPv6 addresses to contact.
 @param host_ip - the IPv6 address of this host.
 @param num_host - the total number of hosts within the network.
 @return - list of IPv6 addresses to contact.
"""
def neighbour_ipv6(host_ip, num_host):
    neighbours = []
    for i in range(1,num_host+1):
        neighbours.append(NETWORK_IPV6 + str(hex(i))[2:])
    neighbours.remove(host_ip)
    return neighbours
 
"""
 Using SSH (from Paramiko) scan the specified TCP destination port.

 @param ip4_dst - destination to ping.
 @param port_dst - destination port to scan.
 @return - True if the host received an answer, False otherwise.
"""
def send_tcp_dest(ip6_dst, port_dst):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(ip6_dst+HOST1_INTERFACE, port=port_dst, timeout=TIMEOUT)
    except socket.error:
        return True
    except socket.timeout:
        return False
    except:
        # We should never get here, but just in case...
        logging.info("[!] FATAL EXCEPTION from Paramiko SSH. Closing tests!")
        print("[!] FATAL EXCEPTION from Paramiko SSH. Closing tests!")
        sys.exit(1)

"""
 Summary of the test here.

 @param num_hosts - the total number of hosts within the network
"""
def test(num_hosts):
    # check that host IP is in 10.0.0.0/24 subnet
    host_ip6 = get_host_ipv6()
    neighbours_ipv6 = neighbour_ipv6(host_ip6, num_hosts)
    print("Beginning test \'" + TEST_NAME + "\'.\n\tCheck " +
          FILENAME_LOG_RESULTS + " for test results once the test"
          " has finished.")
    logging.info("Beginning test \'"+TEST_NAME+"\'") # test name here
    logging.info("\tHost IPv6 address: " + host_ip6)

    failed = []
    test_count = 0

    # IPv6 ICMPv6
    for n in neighbours_ipv6:
        for dst in PORT_NUM_DST:
            logging.info("\t{0} --TCP(src:ephemeral,dst:{1})--> {2}".format(host_ip6,dst,n)) 
            print("\t{0} --TCP(src:ephemeral,dst:{1})--> {2}".format(host_ip6,dst,n)) 
            if not send_tcp_dest(n, dst):
                failed.append("\tFAILED: {0} --TCP(src:ephermeral,dst;{1})--> {2}".format(host_ip6,dst,n))
            test_count += 1

    # See if anything failed
    if len(failed) != 0:
        logging.warning("\tFailed {0}/{1} tests.".format(len(failed),test_count))
        print("\tFailed {0}/{1} tests.".format(len(failed),test_count))
        for f in failed:
            logging.warning("\t{0}".format(f))
    else:
        logging.info("\tPassed {0}/{0} tests. ".format(test_count))
        print("\tPassed {0}/{0} tests. ".format(test_count))

    logging.info("Test \'"+TEST_NAME+"\' complete.")
    print("Test complete. Check " + FILENAME_LOG_RESULTS +
          " for details.")

if __name__ == "__main__":
    TEST_NAME = os.path.basename(__file__)
    FILENAME_LOG_RESULTS = TEST_NAME[:-3] + "_results.log"
    
    # Check command-line arguments
    if len(sys.argv) != 2:
        print("ERROR: Usage: python " + TEST_NAME + " " +
               TEST_SCRIPT_ARGS)
        sys.exit(2)
    try:
        arg = int(sys.argv[1])
        if arg < 2 or arg > 254:
            raise
    except:
        print("ERROR: Argument has be a positive int within range 2-254")
        sys.exit(2)
    # Log file
    logging.basicConfig(filename=FILENAME_LOG_RESULTS,
                        format='%(asctime)s %(message)s',
                        level=logging.DEBUG)
    # Begin the test
    test(int(sys.argv[1]))

