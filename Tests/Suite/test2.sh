#!/bin/bash
#
# Send rules to ACLSwitch to be inserted into the ACL.
#
# Template:
# curl -X PUT -d '{"ip_src":"10.0.0.X", "ip_dst":"10.0.0.Y", "tp_proto":"Z", "port_src":"A", "port_dst":"B"}' http://127.0.0.1:8080/acl_switch
#
