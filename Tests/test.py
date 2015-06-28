# A test script which utilises Scapy. The output of the test is stored
# within the file 'test_out.log'. Note that the definitions of success and
# failure of a test depend on the context. For the purposes of this project,
# a failure would result from packets not being blocked.
# Author: Jarrod N. Bakker

import logging
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
def testPing(ip_dst, n):
    logging.info("Beginning test \'testPing\'")
    logging.info("\tSending " + str(n) + " ICMP ping to " + str(ip_dst))
    #send(IP(dst=ip_dst)/ICMP())
    pings = (IP(dst=ip_dst)/ICMP())
    resp = srloop(pings, count=n)
    # Count how many ICMP replies were received. If 0 were received then
    # the test passed.
    num_replies = countReplies(resp)
    if num_replies != 0:
        logging.warning("\t\'testPing\' failed. " + str(num_replies) +
                        " of " + str(n) + " ping replies were received.")
    else:
        logging.info("\t\'testPing\' passed. All ping requests were unable to be served.")
    logging.info("Finishing test \'testPing\'")

if __name__ == "__main__":
    logging.basicConfig(filename="test_out.log",
                        format='%(asctime)s %(message)s',
                        level=logging.DEBUG)
    testPing("10.0.0.3", 10)
