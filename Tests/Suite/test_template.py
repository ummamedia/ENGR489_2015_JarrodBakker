# Test script template
#
###########################
# Insert test details here.
###########################
#
# NOTE: The script assumes that the host is part of the 10.0.0.0/24 subnet.
#
# Author: Jarrod N. Bakker

import logging
import netifaces as ni
import sys
from scapy.all import *

FILENAME_LOG_RESULTS = "test_results.log"
NETWORK_IPV4 = "10.0.0."

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
    print("Begging test \'TESTNAME\'.\n\tCheck " + FILENAME_LOG_RESULTS
          + " for test results once the test has finished.")
    #logging.info("Beginning test \'TESTNAME\'") # test name here
    #logging.info("\t") # use for general information and test passed
    #logging.warning("\t") # use when something goes wrong i.e. test failed
    logging.info("\tHost IPv4 address: " + host_ip)
    #logging.info("Test \'TESTNAME\' complete.")
    print("Test complete. Check " + FILENAME_LOG_RESULTS +
          " for details.")

if __name__ == "__main__":
    # Check command-line arguments
    if len(sys.argv) != 2:
        print("ERROR: Usage: python test1_noRulesNoBlock.py <number of "
               " hosts in network>")
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

