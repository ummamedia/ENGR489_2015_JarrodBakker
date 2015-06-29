# Test 1: There should be no rules which block traffic between the hosts.
#         Connectivity will be tested through ping requests.
# Usage: python test1_noRulesNoBlock.py <target host in dotted decimal> <number of pings>
# Test success: All ping requests are served by echo replies.
# Test failure: None of the ping requests are served by echo replies.
#
# This test script utilises Scapy. The output of the test is stored within
# the file 'test_out.log'. Note that the definitions of success and failure
# of a test depend on the context (see above).
#
# Author: Jarrod N. Bakker

import logging
import sys
from scapy.all import *

# Count the number ICMP ping replies received by the host. If none were
# received then return 0, else return the number counted. Note that the
# ICMP type for an echo-reply is the integer value 0.
def countReplies(recPingReply):
    count = 0
    for pkt in recPingReply[0]:
        if pkt[1][1].type == 0:
            count += 1
    return count

# This test sends n ping requests to the host ip_dst and expects to
# receive n replies.
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
    if len(sys.argv) != 3:
        print "ERROR: Usage: python test1_noRulesNoBlock.py <target host in dotted decimal> <number of pings>"
        sys.exit(2)
    logging.basicConfig(filename="test_out.log",
                        format='%(asctime)s %(message)s',
                        level=logging.DEBUG)
    noRulesNoBlock(str(sys.argv[1]), int(sys.argv[2]))
