#!/usr/bin/env python

#
# Test: Verify that select packets with a UDP header get blocked when
#       it is destined for from host 1. Care must be taken that this test
#       is run on host 1 with an IPv4 address of 10.0.0.1. The ACL rules
#       can be found in DropSelectH1Dest_IPv4UDP_rules.json
#
# Usage: python DropSelectH1Dest_IPv4UDP.py <number of hosts in the network>
#
# Test success: All traffic receives some form of response (dependent 
#               on protocol).
# Test failure: At least one flow does not received an answer.
#
# Note:
#   - Test output can be found in DropSelectH1Dest_IPv4UDP_results.log
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
import random
import requests
import sys

FILENAME_LOG_RESULTS = None
NETWORK_IPV4 = "10.0.0."

PORT_NUM_DST1 = [1000,1001,1002,1003,1004]
PORT_NUM_SRC1 = [1000,10000,2000,20000]

PORT_NUM_DST2 = [20,21,22,23,80,123,194,6633,8080,8333]

PORT_NUM_SRC3 = [3000,3001,3002,3003,3004,3005,3006,3007,3008,3009]

TEST_SCRIPT_ARGS = "<number of hosts in the network>"
TEST_NAME = None
TIMEOUT = 1
TIME_SLEEP = 1

"""
 Generate a random port number between 32768 and 61000.
 @return - a port number.
"""
def generate_port_num():
    return random.randint(32768, 61000)

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
                  # we should never get here!
    # UDP needs space and time on the receiving host to process requests
    # when we flood them. So we're going to sleep for a wee bit.
    sleep(TIME_SLEEP)
    return len(resp[0]) == 1

"""
 Summary of the test here.

 @param num_hosts - the total number of hosts within the network
"""
def test(num_hosts):
    # check that host IP is in 10.0.0.0/24 subnet
    host_ip4 = get_host_ipv4()
    if NETWORK_IPV4 not in host_ip4:
        print("ERROR: Host IPv4 address not in 10.0.0.0/24 subnet.")
        sys.exit(1)
    neighbours_ipv4 = neighbour_ipv4(host_ip4, num_hosts)
    print("Beginning test \'" + TEST_NAME + "\'.\n\tCheck " +
          FILENAME_LOG_RESULTS + " for test results once the test"
          " has finished.")
    logging.info("Beginning test \'"+TEST_NAME+"\'") # test name here
    logging.info("\tHost IPv4 address: " + host_ip4)

    failed = []
    test_count = 0

    # IPv4 UDP
    for n in neighbours_ipv4:
        for src in PORT_NUM_SRC1:
            for dst in PORT_NUM_DST1:
                logging.info("\t{0} --UDP(src:{1},dst:{2})--> {3}"
                             .format(host_ip4,src,dst,n)) 
                print("\t{0} --UDP(src:{1},dst:{2})--> {3}"
                      .format(host_ip4,src,dst,n))
                if send_udp(n,src,dst):
                    failed.append("\tFAILED: {0} --UDP(src:{1},dst:{2})--> {3}"
                                  .format(host_ip4,src,dst,n))
                test_count += 1

    for n in neighbours_ipv4:
        for dst in PORT_NUM_DST2:
            src = generate_port_num()
            logging.info("\t{0} --UDP(src:{1} (random seeded),dst:{1})--> {2}"
                         .format(host_ip4,src,dst,n)) 
            print("\t{0} --UDP(src:{1} (random seeded),dst:{1})--> {2}"
                  .format(host_ip4,src,dst,n))
            if send_udp(n, src, dst):
                failed.append("\tFAILED: {0} --UDP(src:{1} (random seeded),dst:{1})--> {2}"
                              .format(host_ip4,src,dst,n))
            test_count += 1

    for n in neighbours_ipv4:
        for src in PORT_NUM_SRC3:
            dst = generate_port_num()
            logging.info("\t{0} --UDP(src:{1},dst:{2} (random seeded))--> {2}"
                         .format(host_ip4,src,dst,n)) 
            print("\t{0} --UDP(src:{1},dst:{2} (random seeded))--> {2}"
                  .format(host_ip4,src,dst,n))
            if send_udp(n, src, dst):
                failed.append("\tFAILED: {0} --UDP(src:{1},dst:{2} (random seeded))--> {2}"
                              .format(host_ip4,src,dst,n))
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
    
    random.seed(999)
    
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

