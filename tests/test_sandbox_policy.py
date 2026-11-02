import json
import unittest
from tools.sandbox_policy import PolicyError, load_policy, evaluate_admission

def policy():
    return {"policy_version":"1.0","profile_id":"test","limits":{"cpu_millis":1000,"memory_bytes":1048576,"wall_time_seconds":10,"processes":2,"output_bytes":1000},"filesystem":{"read_only_root":True,"read_paths":["/app"],"write_paths":[]},"network":{"default_deny":True,"egress_allowlist":[]},"execution":{"allow_execution":False,"require_identity":True,"require_policy":True,"require_stop_state":True,"require_artifact_verification":True}}

class SandboxPolicyTests(unittest.TestCase):
    def test_valid_policy(self):
        self.assertEqual(load_policy(json.dumps(policy()))["profile_id"],"test")
    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(PolicyError): load_policy('{"policy_version":"1.0","policy_version":"1.0"}')
    def test_extra_fields_rejected(self):
        p=policy(); p["unexpected"]=True
        with self.assertRaises(PolicyError): load_policy(json.dumps(p))
    def test_boolean_not_integer_limit(self):
        p=policy(); p["limits"]["processes"]=True
        with self.assertRaises(PolicyError): load_policy(json.dumps(p))
    def test_resource_limit_ceiling(self):
        p=policy(); p["limits"]["memory_bytes"]=999999999999
        with self.assertRaises(PolicyError): load_policy(json.dumps(p))
    def test_filesystem_traversal_rejected(self):
        p=policy(); p["filesystem"]["read_paths"]=["/app/../etc"]
        with self.assertRaises(PolicyError): load_policy(json.dumps(p))
    def test_root_must_be_read_only(self):
        p=policy(); p["filesystem"]["read_only_root"]=False
        with self.assertRaises(PolicyError): load_policy(json.dumps(p))
    def test_network_default_deny_required(self):
        p=policy(); p["network"]["default_deny"]=False
        with self.assertRaises(PolicyError): load_policy(json.dumps(p))
    def test_execution_cannot_be_enabled_in_reference(self):
        p=policy(); p["execution"]["allow_execution"]=True
        with self.assertRaises(PolicyError): load_policy(json.dumps(p))
    def test_missing_stop_state_denies(self):
        self.assertEqual(evaluate_admission(authenticated=True,policy_allowed=True,artifact_verified=True,revocation_clear=True,stop_state_valid=False,stop_active=False,backend_enforced=True)[0],False)
    def test_active_stop_denies(self):
        self.assertEqual(evaluate_admission(authenticated=True,policy_allowed=True,artifact_verified=True,revocation_clear=True,stop_state_valid=True,stop_active=True,backend_enforced=True)[0],False)
    def test_backend_missing_denies(self):
        self.assertEqual(evaluate_admission(authenticated=True,policy_allowed=True,artifact_verified=True,revocation_clear=True,stop_state_valid=True,stop_active=False,backend_enforced=False)[0],False)
    def test_all_checks_still_non_executing(self):
        allowed, reason=evaluate_admission(authenticated=True,policy_allowed=True,artifact_verified=True,revocation_clear=True,stop_state_valid=True,stop_active=False,backend_enforced=True)
        self.assertFalse(allowed); self.assertEqual(reason,"deny:reference-implementation-never-executes")

if __name__ == "__main__": unittest.main()
