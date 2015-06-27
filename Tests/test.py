# A test script which utilises Scapy. The output of the test is stored
# within the file 'test_out.log'.
# Author: Jarrod N. Bakker

import logging
from scapy.all import *

def testPing():
    logging.info("Beginning test \'testPing\'")
    send(IP(dst="10.0.0.2")/ICMP())
    logging.info("Finishing test \'testPing\'")

if __name__ == "__main__":
    logging.basicConfig(filename="test_out.log",
                        format='%(asctime)s %(message)s',
                        level=logging.DEBUG)
    testPing()
