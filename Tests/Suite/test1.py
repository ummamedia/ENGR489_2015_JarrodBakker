#
# Test 1: This test is used to verify that traffic can pass reach its
#         intended destination when there are no rules in the firewall's
#         ACL. Only hosts within the network should be attempted to be
#         reached. Due to the numerous combinations of source and
#         destination ports that can be made, only a subset of the
#         combinations will be used.
#
#         IPv4 address are used as well as ICMP, TCP and UDP.
#
# Usage: python test1.py <number of hosts in the network>
#
# Test success: All requests receive replies.
# Test failure: At least one request is unanswered.
#
# Note:
#   - Test output can be found in test_results.log
#
#   - Scapy is used for packet manipulation.
#
#   - The script assumes that the host is part of the 10.0.0.0/24
#     subnet.
#
# Author: Jarrod N. Bakker
#

import logging
import netifaces as ni
import sys
from scapy.all import *

FILENAME_LOG_RESULTS = "test_results.log"
NETWORK_IPV4 = "10.0.0."
TEST_NAME = "No ACL Rules - check blocking"
TEST_SCRIPT_NAME = "test1.py"
TEST_SCRIPT_ARGS = "<number of hosts in the network>"

"""
 Count the number ICMP ping replies received by the host. If none were
 received then return 0, else return the number counted. Note that the
 ICMP type for an echo-reply is the integer value 0.
"""
def count_replies(recPingReply):
    count = 0
    for pkt in recPingReply[0]:
        if pkt[1][1].type == 0:
            count += 1
    return count

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
 Summary of the test here.

 @param num_hosts - the total number of hosts within the network
"""
def test(num_hosts):
    # check that host IP is in 10.0.0.0/24 subnet
    host_ip = get_host_ipv4()
    if NETWORK_IPV4 not in host_ip:
        print("ERROR: Host IPv4 address not in 10.0.0.0/24 subnet.")
        sys.exit(1)
    neighbours = neighbour_ipv4(host_ip, num_hosts)
    print("Beginning test \'" + TEST_NAME + "\'.\n\tCheck " +
          FILENAME_LOG_RESULTS + " for test results once the test"
          " has finished.")
    #logging.info("Beginning test \'TESTNAME\'") # test name here
    #logging.info("\t") # use for general information and test passed
    #logging.warning("\t") # use when something goes wrong i.e. test failed
    logging.info("\tHost IPv4 address: " + host_ip)
    #logging.info("Test \'TESTNAME\' complete.")
    print("Test complete. Check " + FILENAME_LOG_RESULTS +
          " for details.")

"""
 This test sends n ping requests to the host ip_dst and expects to
 receive n replies.
"""
def noRulesNoBlock(ip_dst, n):
    logging.info("Beginning test \'noRulesNoBlock\'")
    logging.info("\tSending " + str(n) + " ICMP ping(s) to " + str(ip_dst))
    pings = (IP(dst=ip_dst)/ICMP())
    resp = srloop(pings, count=n)
    # Count how many ICMP replies were received. If 0 were received then
    # the test passed.
    num_replies = countReplies(resp)
    if num_replies == 0:
        logging.warning("\tTest \'noRulesNoBlock\' failed. No ping replies were received.")
    elif num_replies != n and num_replies != 0:
        logging.warning("\tTest \'noRulesNoBlock\' failed. " + str(num_replies)
                        + " of " + str(n) + " ping replies received.")
    else:
        logging.info("\tTest \'noRulesNoBlock\' passed. All ping requests were able to be served.")
    logging.info("Finishing test \'noRulesNoBlock\'")

if __name__ == "__main__":
    # Check command-line arguments
    if len(sys.argv) != 2:
        print("ERROR: Usage: python " + TEST_SCRIPT_NAME + " " +
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

