# Test X: There should be rules which block TCP traffic between the hosts.
#         The target host should be blocking specific TCP traffic for this
#         test scenario. The client will try a set of TCP ports and will
#         wait for all attempted connections to timeout.
#         The following ports will be tested: 22, 40, 118, 194 and 8080.
# Usage: python test_tcpBlockSpecific.py <target host in dotted decimal>
# Test success: All TCP requests timeout.
# Test failure: All or some TCP requests are served.
#
# This test script utilises Scapy. The output of the test is stored within
# the file 'test_out.log'. Note that the definitions of success and failure
# of a test depend on the context (see above).
#
# Author: Jarrod N. Bakker

import logging
import sys
from scapy.all import *

# Count the number TCP connections which weren't blocked i.e. did not
# time out.
def countResp(recTCPResp):
    count = 0
    for pkt in recTCPResp:
        if len(pkt[0]) == 1:
            count += 1
    return count

# This test sends n ping requests to the host ip_dst and expects to
# receive n replies.
def tcpBlockSpecific(ip_dst):
    logging.info("Beginning test \'tcpBlockSpecific\'")
    logging.info("\tSending TCP SYN packets to " + str(ip_dst) + " using destination ports: 22, 40, 118, 194 and 8080")
    # Form the tcp requests
    tcp1 = TCP(sport=16, dport=22, seq=100, flags="S")
    tcp2 = TCP(sport=16, dport=40, seq=100, flags="S")
    tcp3 = TCP(sport=16, dport=118, seq=100, flags="S")
    tcp4 = TCP(sport=16, dport=194, seq=100, flags="S")
    tcp5 = TCP(sport=16, dport=8080, seq=100, flags="S")
    # and the IP header...
    ip = IP(dst=ip_dst)
    # Now for test!
    resp_list = []
    resp_list.append(sr(ip/tcp1, timeout=2))
    resp_list.append(sr(ip/tcp2, timeout=2))
    resp_list.append(sr(ip/tcp3, timeout=2))
    resp_list.append(sr(ip/tcp4, timeout=2))
    resp_list.append(sr(ip/tcp5, timeout=2))
    # Count the number of connections that weren't blocked.
    num_resp = countResp(resp_list)
    if num_resp > 0:
        logging.warning("\tTest \'tcpBlockSpecific\' failed. " +
                        str(num_resp) +
                        " of 5 TCP connections received responses.")
    else:
        logging.info("\tTest \'tcpBlockSpecific\' passed. No ping requests were able to be served.")
    logging.info("Finishing test \'tcpBlockSpecific\'")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "ERROR: Usage: python test_tcpBlockSpecific.py <target host in dotted decimal>"
        sys.exit(2)
    logging.basicConfig(filename="test_out.log",
                        format='%(asctime)s %(message)s',
                        level=logging.DEBUG)
    tcpBlockSpecific(str(sys.argv[1]))
