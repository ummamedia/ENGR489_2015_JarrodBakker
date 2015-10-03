#!/usr/bin/env python

#
# Test: Verify that traffic can follow through the network when there
#       are no rules in the ACL.
#
# Usage: python NoDrop_EmptyACL.py <number of hosts in the network>
#
# Test success: All traffic receives some form of response (dependent 
#               on protocol).
# Test failure: At least one flow does not received an answer.
#
# Note:
#   - Test output can be found in NoDrop_EmptyACL_results.log
#
#   - Scapy is used for packet manipulation.
#
#   - The script assumes that the host is part of the 10.0.0.0/24
#     subnet.
#
#   - The script assumes that the syntax for the REST commands are
#     legal.
#
# Author: Jarrod N. Bakker
#

from scapy.all import *
from time import sleep
import json
import logging
import netifaces as ni
import os
import requests
import sys

FILENAME_LOG_RESULTS = None
NETWORK_IPV4 = "10.0.0."
NETWORK_IPV6 = "fe80::200:ff:fe00:"
PORT_NUM_DST = [14,16,20,21,22,23,80,123,8080,9001]
PORT_NUM_SRC = [4001,4002,4003,4004,4005,5011,5012,5013,5014]
TEST_SCRIPT_ARGS = "<number of hosts in the network>"
TEST_NAME = None
TIMEOUT = 1
TIME_SLEEP = 1

"""
 Fetch and return the IPv4 address of THIS host from interface h#_eth0
 where # is the host number.
 @return - the IPv4 address of the host's h#_eth0 interface
"""
def get_host_ipv4():
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
    host_ipv4 = ni.ifaddresses(host_iface)[ni.AF_INET][0]["addr"]
    return host_ipv4

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
 Create the list of IPv4 addresses to contact.
 @param host_ip - the IPv4 address of this host.
 @param num_host - the total number of hosts within the network.
 @return - list of IPv4 addresses to contact.
"""
def neighbour_ipv4(host_ip, num_host):
    neighbours = []
    for i in range(1,num_host+1):
        neighbours.append(NETWORK_IPV4 + str(i))
    neighbours.remove(host_ip)
    return neighbours

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
 Send an ICMP ping to the destination host and inform the caller if a
 response was received.
 @param ip4_dst - destination to ping.
 @return - True if the host received an answer, False otherwise.
"""
def send_icmp(ip4_dst):
    resp = sr(IP(dst=ip4_dst)/ICMP(),timeout=TIMEOUT)
    return len(resp[0]) == 1

"""
 Send an TCP header to the destination host and inform the caller if a
 response was received.
 @param ip4_dst - destination to ping.
 @param port_src - source port.
 @param port_dst - destation port.
 @return - True if the host received an answer, False otherwise.
"""
def send_tcp(ip4_dst, port_src, port_dst):
    resp = sr(IP(dst=ip4_dst)/TCP(sport=port_src,dport=port_dst,
              flags="S"),timeout=TIMEOUT)
    return len(resp[0]) == 1

"""
 Send an UDP header to the destination host and inform the caller if a
 response was received.
 @param ip4_dst - destination to ping.
 @param port_src - source port.
 @param port_dst - destation port.
 @return - True if the host received an answer, False otherwise.
"""
def send_udp(ip4_dst, port_src, port_dst):
    resp = sr(IP(dst=ip4_dst)/UDP(sport=port_src,dport=port_dst),
              timeout=TIMEOUT)
    # UDP needs space and time on the receiving host to process requests
    # when we flood them. So we're going to sleep for a wee bit.
    sleep(TIME_SLEEP)
    return len(resp[0]) == 1

"""
 Send an ICMPv6 ping to the destination host and inform the caller if a
 response was received.
 @param ip4_dst - destination to ping.
 @return - True if the host received an answer, False otherwise.
"""
def send_icmpv6(ip6_dst):
    resp = sr(IPv6(dst=ip6_dst)/ICMPv6EchoRequest(),timeout=TIMEOUT)
    return len(resp[0]) == 1

"""
 Summary of the test here.

 @param num_hosts - the total number of hosts within the network
"""
def test(num_hosts):
    # check that host IP is in 10.0.0.0/24 subnet
    host_ip4 = get_host_ipv4()
    host_ip6 = get_host_ipv6()
    if NETWORK_IPV4 not in host_ip4:
        print("ERROR: Host IPv4 address not in 10.0.0.0/24 subnet.")
        sys.exit(1)
    neighbours_ipv4 = neighbour_ipv4(host_ip4, num_hosts)
    neighbours_ipv6 = neighbour_ipv6(host_ip6, num_hosts)
    print("Beginning test \'" + TEST_NAME + "\'.\n\tCheck " +
          FILENAME_LOG_RESULTS + " for test results once the test"
          " has finished.")
    logging.info("Beginning test \'"+TEST_NAME+"\'") # test name here
    logging.info("\tHost IPv4 address: " + host_ip4)
    logging.info("\tHost IPv6 address: " + host_ip6)

    failed = []
    test_count = 0

    # IPv4 ICMP
    for n in neighbours_ipv4:
        logging.info("\t{0} --ICMP ping--> {1}".format(host_ip4,n)) 
        print("\t{0} --ICMP ping--> {1}".format(host_ip4,n)) 
        if not send_icmp(n):
            failed.append("\tFAILED: {0} --ICMP ping--> {1}".format(host_ip4,n))
        test_count += 1

    # IPv4 TCP
    for n in neighbours_ipv4:
        for src in PORT_NUM_SRC:
            for dst in PORT_NUM_DST:
                logging.info("\t{0} --TCP(src:{1},dst:{2})--> {3}"
                             .format(host_ip4,src,dst,n)) 
                print("\t{0} --TCP(src:{1},dst:{2})--> {3}"
                      .format(host_ip4,src,dst,n))
                if not send_tcp(n,src,dst):
                    failed.append("\tFAILED: {0} --TCP(src:{1},dst:{2})--> {3}"
                                  .format(host_ip4,src,dst,n))
                test_count += 1

    # IPv4 UDP
    for n in neighbours_ipv4:
        for src in PORT_NUM_SRC:
            for dst in PORT_NUM_DST:
                logging.info("\t{0} --UDP(src:{1},dst:{2})--> {3}"
                             .format(host_ip4,src,dst,n)) 
                print("\t{0} --UDP(src:{1},dst:{2})--> {3}"
                      .format(host_ip4,src,dst,n))
                if not send_udp(n,src,dst):
                    failed.append("\tFAILED: {0} --UDP(src:{1},dst:{2})--> {3}"
                                  .format(host_ip4,src,dst,n))
                test_count += 1

    # IPv6 ICMPv6
    for n in neighbours_ipv6:
        logging.info("\t{0} --ICMPv6 ping--> {1}".format(host_ip6,n)) 
        print("\t{0} --ICMPv6 ping--> {1}".format(host_ip6,n)) 
        if not send_icmpv6(n):
            failed.append("\tFAILED: {0} --ICMPv6 ping--> {1}".format(host_ip6,n))
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

