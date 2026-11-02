"""Fail-closed sandbox policy validator; deliberately does not execute workloads."""
from __future__ import annotations
import json
from pathlib import PurePosixPath

class PolicyError(ValueError):
    pass

def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise PolicyError(f"duplicate key: {key}")
        out[key] = value
    return out

def load_policy(raw: str) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda x: (_ for _ in ()).throw(PolicyError(f"invalid number: {x}")))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise PolicyError("invalid JSON") from exc
    if not isinstance(value, dict):
        raise PolicyError("policy must be an object")
    return validate_policy(value)

def _integer(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise PolicyError(f"{name} outside permitted range")

def _paths(values, name):
    if not isinstance(values, list) or any(not isinstance(x, str) or not x.startswith("/") or "\x00" in x for x in values):
        raise PolicyError(f"{name} must contain absolute POSIX paths")
    if len(set(values)) != len(values):
        raise PolicyError(f"{name} contains duplicates")
    for item in values:
        if ".." in PurePosixPath(item).parts:
            raise PolicyError(f"{name} contains traversal path")

def validate_policy(p: dict) -> dict:
    required = {"policy_version","profile_id","limits","filesystem","network","execution"}
    if set(p) != required or p.get("policy_version") != "1.0":
        raise PolicyError("unknown, missing, or unsupported policy fields")
    if not isinstance(p["profile_id"], str) or not p["profile_id"] or len(p["profile_id"]) > 128:
        raise PolicyError("invalid profile_id")
    limits = p["limits"]
    if not isinstance(limits, dict) or set(limits) != {"cpu_millis","memory_bytes","wall_time_seconds","processes","output_bytes"}:
        raise PolicyError("invalid limits")
    for name, low, high in [("cpu_millis",1,60000),("memory_bytes",1048576,17179869184),("wall_time_seconds",1,86400),("processes",1,256),("output_bytes",0,104857600)]:
        _integer(limits[name], name, low, high)
    fs = p["filesystem"]
    if not isinstance(fs, dict) or set(fs) != {"read_only_root","read_paths","write_paths"} or fs["read_only_root"] is not True:
        raise PolicyError("filesystem must use read-only root and explicit paths")
    _paths(fs["read_paths"], "read_paths")
    _paths(fs["write_paths"], "write_paths")
    net = p["network"]
    if not isinstance(net, dict) or set(net) != {"default_deny","egress_allowlist"} or net["default_deny"] is not True:
        raise PolicyError("network must default deny")
    if not isinstance(net["egress_allowlist"], list) or any(not isinstance(x,str) or not x or len(x)>255 for x in net["egress_allowlist"]):
        raise PolicyError("invalid egress allowlist")
    if len(set(net["egress_allowlist"])) != len(net["egress_allowlist"]):
        raise PolicyError("duplicate egress entries")
    ex = p["execution"]
    expected = {"allow_execution","require_identity","require_policy","require_stop_state","require_artifact_verification"}
    if not isinstance(ex, dict) or set(ex) != expected:
        raise PolicyError("invalid execution requirements")
    if ex["allow_execution"] is not False:
        raise PolicyError("reference release cannot enable workload execution")
    for key in expected - {"allow_execution"}:
        if ex[key] is not True:
            raise PolicyError(f"{key} must be true")
    return p

def evaluate_admission(*, authenticated: bool, policy_allowed: bool, artifact_verified: bool, revocation_clear: bool, stop_state_valid: bool, stop_active: bool, backend_enforced: bool) -> tuple[bool, str]:
    checks = {
        "identity": authenticated is True,
        "policy": policy_allowed is True,
        "artifact": artifact_verified is True,
        "revocation": revocation_clear is True,
        "stop-state": stop_state_valid is True,
        "stop-inactive": stop_active is False,
        "isolation-backend": backend_enforced is True,
    }
    for name, value in checks.items():
        if value is not True:
            return False, f"deny:{name}"
    return False, "deny:reference-implementation-never-executes"
