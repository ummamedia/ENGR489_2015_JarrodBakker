# Author: Jarrod N. Bakker
# Part of an ENGR489 project at Victoria University of Wellington
# during 2015.
#
# This class manages the RESTful API calls to add rules etc.
#
# The RESTful interface code has been adapted from
# http://osrg.github.io/ryu-book/en/html/rest_api.html.
#

# Modules
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import route
from webob import Response
import json

# Global field needed for REST linkage
acl_switch_instance_name = "acl_switch_app"
url = "/acl_switch"

class ACLSwitchREST(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(ACLSwitchREST, self).__init__(req, link, data, **config)
        self.acl_switch_inst = data[acl_switch_instance_name]
   
    """
    API call to return info on ACLSwitch. The number of roles, rules,
    switches and the current time of the machine that ACLSwitch is
    running on are returned. This should only be taken as an
    approximation of the current time therefore the time should only
    be accurate within minutes.

    """
    @route("acl_switch", url, methods=["GET"])
    def return_aclswitch_info(self, req, **kwargs):
        aclswitch_info = self.acl_switch_inst.get_info()
        body = json.dumps(aclswitch_info)
        return Response(content_type="application/json", body=body)

    """
    API call to show the switches and the roles associated with them.
    """
    @route("acl_switch", url+"/switches", methods=["GET"])
    def switch_role_list(self, req, **kwargs):
        body = json.dumps(self.acl_switch_inst.get_switches())
        return Response(content_type="application/json", body=body)

    """
    API call to return a list of the currently available roles.
    """
    @route("acl_switch", url+"/switch_roles", methods=["GET"])
    def role_list(self, req, **kwargs):
        body = json.dumps({"Roles":self.acl_switch_inst.get_role_list()})
        return Response(content_type="application/json", body=body)
    
    """
    API call to return the current contents of the ACL.
    """
    @route("acl_switch", url+"/acl_rules", methods=["GET"])
    def acl_list(self, req, **kwargs):
        acl = self.acl_switch_inst.get_acl()
        body = json.dumps(acl)
        return Response(content_type="application/json", body=body)

    """
    API call to return a list representing the queue of scheduled 
    """
    @route("acl_switch", url+"/acl_rules/time", methods=["GET"])
    def time_queue_list(self, req, **kwargs):
        body = json.dumps(self.acl_switch_inst.get_time_queue())
        return Response(content_type="application/json", body=body)

    """
    API call to create a role.
    """
    @route("acl_switch", url+"/switch_roles", methods=["POST"])
    def role_create(self, req, **kwargs):
        try:
            create_req = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        try:
            role = create_req["role"]
        except:
            return Response(status=400, body="Invalid JSON passed.")
        result = self.acl_switch_inst.role_create(role)
        if result[0] == True:
            status = 200
        else:
            status = 400
        return Response(status=status, body=result[1])

    """
    API call to delete a role from ACLSwitch.
    """
    @route("acl_switch", url+"/switch_roles", methods=["DELETE"])
    def role_delete(self, req, **kwargs):
        try:
            delete_req = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        try:
            role = delete_req["role"]
        except:
            return Response(status=400, body="Invalid JSON passed.")
        result = self.acl_switch_inst.role_delete(role)
        if result[0] == True:
            status = 200
        else:
            status = 400
        return Response(status=status, body=result[1])

    """
    API call to assign a role to a switch.
    """
    @route("acl_switch", url+"/switch_roles/assignment", methods=["PUT"])
    def role_switch_assign(self, req, **kwargs):
        try:
            assignReq = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        try:
            switch_id = int(assignReq["switch_id"])
            new_role = assignReq["new_role"]
        except:
            return Response(status=400, body="Invalid JSON passed.")
        result = self.acl_switch_inst.switch_role_assign(switch_id,
                                                         new_role)
        if result[0] == True:
            status = 200
        else:
            status = 400
        return Response(status=status, body=result[1])

    """
    API call to remove a role assignment from a switch.
    """
    @route("acl_switch", url+"/switch_roles/assignment", methods=["DELETE"])
    def role_switch_remove(self, req, **kwargs):
        try:
            removeReq = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        try:
            switch_id = int(removeReq["switch_id"])
            old_role = removeReq["old_role"]
        except:
            return Response(status=400, body="Invalid JSON passed.")
        result = self.acl_switch_inst.switch_role_remove(switch_id,
                                                         old_role)
        if result[0] == True:
            status = 200
        else:
            status = 400
        return Response(status=status, body=result[1])

    """
    API call to add a rule to the ACL.
    """
    @route("acl_switch", url+"/acl_rules", methods=["POST"])
    def acl_rule_add(self, req, **kwargs):
        try:
            ruleReq = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        if not self.check_rule_json(ruleReq):
            return Response(status=400, body="Invalid JSON passed.")
        result = self.acl_switch_inst.add_acl_rule(ruleReq["ip_src"],
                                                    ruleReq["ip_dst"],
                                                    ruleReq["tp_proto"],
                                                    ruleReq["port_src"],
                                                    ruleReq["port_dst"],
                                                    ruleReq["role"])
        if result[0] == False:
            return Response(status=400, body=result[1])
        return Response(status=200, body=result[1])

    """
    API call to add a rule which should be enforced for a period of time.
    """
    @route("acl_switch", url+"/acl_rules/time", methods=["POST"])
    def acl_rule_add_time(self, req, ** kwargs):
        try:
            ruleReq = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        if not self.check_rule_time_json(ruleReq):
            return Response(status=400, body="Invalid JSON passed.")
        result = self.acl_switch_inst.add_acl_rule(ruleReq["ip_src"],
                                                        ruleReq["ip_dst"],
                                                        ruleReq["tp_proto"],
                                                        ruleReq["port_src"],
                                                        ruleReq["port_dst"],
                                                        ruleReq["role"],
                                                        ruleReq["time_start"],
                                                        ruleReq["time_duration"])
        if result[0] == False:
            return Response(status=400, body=result[1])
        return Response(status=200, body=result[1])

    """
    API call to remove a rule from the ACL.
    """
    @route("acl_switch", url+"/acl_rules", methods=["DELETE"])
    def acl_rule_remove(self, req, **kwargs):
        try:
            deleteReq = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        result = self.acl_switch_inst.delete_acl_rule(deleteReq["rule_id"])
        if result[0] == True:
            status = 200
        else:
            status = 400
        return Response(status=status, body=result[1])

    """
    Check that incoming JSON for an ACL has the required 6 fields:
    "ip_src", "ip_dst", "tp_proto", "port_src", "port_dst" and "role".
    
    @param ruleJSON - input from the client to check.
    @return - True if ruleJSON is valid, False otherwise.
    """
    def check_rule_json(self, ruleJSON):
        if len(ruleJSON) != 6:
            return False
        if not "ip_src" in ruleJSON:
            return False
        if not "ip_dst" in ruleJSON:
            return False
        if not "tp_proto" in ruleJSON:
            return False
        if not "port_src" in ruleJSON:
            return False
        if not "port_dst" in ruleJSON:
            return False
        if not "role" in ruleJSON:
            return False
        return True # everything is looking good!

    """
    Check that incoming JSON for an ACL has the required 6 fields:
    "ip_src", "ip_dst", "tp_proto", "port_src", "port_dst", "role",
    "time_start" and "time_duration".
    
    @param ruleJSON - input from the client to check.
    @return - True if ruleJSON is valid, False otherwise.
    """
    def check_rule_time_json(self, ruleJSON):
        if len(ruleJSON) != 8:
            return False
        if not "ip_src" in ruleJSON:
            return False
        if not "ip_dst" in ruleJSON:
            return False
        if not "tp_proto" in ruleJSON:
            return False
        if not "port_src" in ruleJSON:
            return False
        if not "port_dst" in ruleJSON:
            return False
        if not "role" in ruleJSON:
            return False
        if not "time_start" in ruleJSON:
            return False
        if not "time_duration" in ruleJSON:
            return False
        return True # everything is looking good!

