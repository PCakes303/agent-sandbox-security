import json
import unittest
from pathlib import Path
from jsonschema import Draft202012Validator
from tools.sandbox_policy import PolicyError, load_policy, validate_policy, evaluate_admission

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
    def test_non_boolean_admission_evidence_denies(self):
        self.assertFalse(evaluate_admission(authenticated=1,policy_allowed=True,artifact_verified=True,revocation_clear=True,stop_state_valid=True,stop_active=False,backend_enforced=True)[0])

    def test_all_checks_still_non_executing(self):
        allowed, reason=evaluate_admission(authenticated=True,policy_allowed=True,artifact_verified=True,revocation_clear=True,stop_state_valid=True,stop_active=False,backend_enforced=True)
        self.assertFalse(allowed); self.assertEqual(reason,"deny:reference-implementation-never-executes")

    def test_policy_input_byte_limit_is_enforced_before_parse(self):
        with self.assertRaisesRegex(PolicyError, "byte limit"):
            load_policy(" " * (1_048_576 + 1))

    def test_policy_json_nesting_limit_is_enforced_before_parse(self):
        raw = '{"nested":' + ("[" * 33) + "0" + ("]" * 33) + "}"
        with self.assertRaisesRegex(PolicyError, "depth limit"):
            load_policy(raw)

    def test_escaped_braces_and_brackets_inside_strings_do_not_count_as_depth(self):
        value = policy()
        value["network"]["egress_allowlist"] = ['host.example/{[text]}?q="value"']
        self.assertEqual(load_policy(json.dumps(value))["network"]["egress_allowlist"], ['host.example/{[text]}?q="value"'])

    def test_filesystem_path_count_and_length_are_bounded(self):
        p = policy()
        p["filesystem"]["read_paths"] = [f"/path/{i}" for i in range(65)]
        with self.assertRaises(PolicyError):
            load_policy(json.dumps(p))
        p = policy()
        p["filesystem"]["read_paths"] = ["/" + ("x" * 1024)]
        with self.assertRaises(PolicyError):
            load_policy(json.dumps(p))

    def test_egress_count_and_length_are_bounded(self):
        p = policy()
        p["network"]["egress_allowlist"] = [f"host{i}.example" for i in range(65)]
        with self.assertRaises(PolicyError):
            load_policy(json.dumps(p))
        p = policy()
        p["network"]["egress_allowlist"] = ["x" * 256]
        with self.assertRaises(PolicyError):
            load_policy(json.dumps(p))

    def test_non_text_and_non_object_direct_inputs_are_controlled(self):
        with self.assertRaises(PolicyError):
            load_policy(b"{}")
        with self.assertRaises(PolicyError):
            validate_policy([])

    def test_schema_matches_runtime_security_boundaries(self):
        root = Path(__file__).resolve().parents[1]
        schema = json.loads((root / "schemas/sandbox-policy.schema.json").read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        valid = policy()
        self.assertEqual(list(validator.iter_errors(valid)), [])
        self.assertEqual(load_policy(json.dumps(valid)), valid)
        for mutate in (
            lambda p: p["execution"].update({"allow_execution": True}),
            lambda p: p["limits"].update({"cpu_millis": 60001}),
            lambda p: p["filesystem"].update({"read_paths": ["/app/../etc"]}),
            lambda p: p["filesystem"].update({"read_paths": ["/bad\x00path"]}),
            lambda p: p["filesystem"].update({"read_only_root": False}),
            lambda p: p["filesystem"].update({"read_paths": ["/x"] * 65}),
        ):
            candidate = json.loads(json.dumps(valid))
            mutate(candidate)
            self.assertTrue(list(validator.iter_errors(candidate)))
            with self.assertRaises(PolicyError):
                load_policy(json.dumps(candidate))

if __name__ == "__main__": unittest.main()
