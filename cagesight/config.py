"""Configuration, rule loading and the shared detector context."""

from __future__ import annotations

import copy
import ipaddress
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from cagesight.model import Event, Finding, SEVERITY_SCORE

DEFAULT_DOMAINS = [
    "pypi.org",
    "files.pythonhosted.org",
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "registry.npmjs.org",
    "deb.debian.org",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "api.openai.com",
    "api.anthropic.com",
]

SENSITIVE_PATHS: Dict[str, List[str]] = {
    "ssh": [".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/id_dsa", ".ssh/config"],
    "cloud": [
        ".aws/credentials",
        ".aws/config",
        ".config/gcloud/",
        ".azure/",
        ".aliyun/",
        ".tencentcloud/",
    ],
    "container": [
        "var/run/docker.sock",
        "run/docker.sock",
        "run/containerd/containerd.sock",
        "var/run/crio/crio.sock",
        "run/podman/podman.sock",
        ".kube/config",
        "var/run/secrets/kubernetes.io/serviceaccount/",
        "run/secrets/",
    ],
    "app": [".netrc", ".git-credentials", ".npmrc", ".pypirc", ".docker/config.json", ".config/gh/hosts.yml"],
    "system": ["etc/shadow", "etc/sudoers", "proc/self/environ", "proc/1/environ"],
    "envfiles": [".env", ".env.local", ".env.production", ".env.prod"],
}

DEFAULTS: Dict[str, Any] = {
    "allowlist": {
        "domains": DEFAULT_DOMAINS,
        "cidrs": ["127.0.0.0/8"],
        "ports": [53, 80, 443],
    },
    "thresholds": {
        "dns": {
            "label_len": 30,
            "entropy": 3.4,
            "window_sec": 60,
            "min_queries": 20,
            "unique_ratio": 0.9,
            "suspicious_qtypes": ["TXT", "NULL"],
            "rate_min_label_len": 12,
            "rate_min_entropy": 2.8,
        },
        "net": {"upload_bytes": 5242880, "window_sec": 120, "common_ports": [53, 80, 443]},
        "staging": {"window_sec": 300, "min_files": 3},
    },
    "sensitive_paths": SENSITIVE_PATHS,
    "correlation": {"window_sec": 600, "escape_window_sec": 300},
    "response": {"enforce": False, "webhook": ""},
    "report": {"min_severity": "low"},
}

RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "default.json")


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    config = copy.deepcopy(DEFAULTS)
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            config = deep_merge(config, json.load(handle))
    return config


def load_rules(path: Optional[str] = None) -> Dict[str, Any]:
    with open(RULES_PATH, "r", encoding="utf-8") as handle:
        base = json.load(handle)
    if not path:
        return base
    with open(path, "r", encoding="utf-8") as handle:
        custom = json.load(handle)
    return merge_rules(base, custom)


def merge_rules(base: Dict[str, Any], custom: Any) -> Dict[str, Any]:
    """Merge user overrides into the built-in rule set, keyed by rule id.

    A custom file may contain only the fields to change; rules that are not
    mentioned keep their built-in definition. New ids are appended.
    """
    custom_rules = custom.get("rules", []) if isinstance(custom, dict) else custom
    if not isinstance(custom_rules, list):
        raise ValueError("规则文件格式错误：rules 应为数组")

    merged: Dict[str, Dict[str, Any]] = {rule["id"]: dict(rule) for rule in base.get("rules", [])}
    order = [rule["id"] for rule in base.get("rules", [])]
    for rule in custom_rules:
        if not isinstance(rule, dict) or not rule.get("id"):
            continue
        rule_id = rule["id"]
        if rule_id in merged:
            merged[rule_id].update(rule)
        else:
            merged[rule_id] = dict(rule)
            order.append(rule_id)

    result = dict(base)
    result["rules"] = [merged[rule_id] for rule_id in order]
    return result


NUMERIC_THRESHOLDS = {
    "dns": ("label_len", "entropy", "window_sec", "min_queries", "unique_ratio", "rate_min_label_len", "rate_min_entropy"),
    "net": ("upload_bytes", "window_sec"),
    "staging": ("window_sec", "min_files"),
    "correlation": ("window_sec", "escape_window_sec"),
}


def validate_config(config: Dict[str, Any]) -> None:
    """Fail fast on obviously wrong threshold types instead of silently
    disabling a detector at runtime."""
    for section, keys in NUMERIC_THRESHOLDS.items():
        values = config.get("thresholds", {}).get(section, {}) if section != "correlation" else config.get(section, {})
        if not isinstance(values, dict):
            raise ValueError("配置项 %s 应为对象" % section)
        for key in keys:
            if key not in values:
                continue
            value = values[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("配置项 %s.%s 应为数字，当前为 %r" % (section, key, value))
    for section, key in (("dns", "suspicious_qtypes"), ("net", "common_ports")):
        values = config.get("thresholds", {}).get(section, {})
        if key in values and not isinstance(values[key], list):
            raise ValueError("配置项 %s.%s 应为数组" % (section, key))


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip()


def path_matches(path: str, patterns: List[str]) -> bool:
    """Suffix-style matching against sensitive path patterns.

    Patterns are written relative to any prefix, e.g. ``.ssh/id_rsa`` matches
    ``/home/agent/.ssh/id_rsa`` and ``.config/gcloud/`` matches any file below
    that directory.
    """
    if not path:
        return False
    candidate = normalize_path(path).lower()
    for pattern in patterns:
        pattern = pattern.lower()
        if pattern.endswith("/"):
            if "/" + pattern in candidate or candidate.startswith(pattern):
                return True
        elif candidate.endswith("/" + pattern) or candidate == pattern:
            return True
    return False


def which_sensitive_group(path: str, groups: Dict[str, List[str]]) -> Optional[str]:
    for group, patterns in groups.items():
        if path_matches(path, patterns):
            return group
    return None


def in_cidrs(ip: str, cidrs: List[str]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if address in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_public_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
    )


class Context:
    """Holds config + rule metadata and builds findings."""

    def __init__(self, config: Dict[str, Any], rules: Dict[str, Any]):
        validate_config(config)
        self.config = config
        self.rules = {rule["id"]: rule for rule in rules.get("rules", [])}
        self.thresholds = config.get("thresholds", {})
        self.allowlist = config.get("allowlist", {})
        self.sensitive_paths = config.get("sensitive_paths", SENSITIVE_PATHS)

    # -- rules -----------------------------------------------------------
    def rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        return self.rules.get(rule_id)

    def enabled(self, rule_id: str) -> bool:
        rule = self.rules.get(rule_id)
        return bool(rule and rule.get("enabled", True))

    def severity(self, rule_id: str, override: Optional[str] = None) -> str:
        if override:
            return override
        rule = self.rules.get(rule_id) or {}
        return rule.get("severity", "medium")

    # -- finding factory -------------------------------------------------
    def finding(
        self,
        rule_id: str,
        event: Event,
        evidence: str,
        severity: Optional[str] = None,
        tags: Optional[Tuple[str, ...]] = None,
        description: Optional[str] = None,
        score_delta: int = 0,
    ) -> Optional[Finding]:
        if not self.enabled(rule_id):
            return None
        rule = self.rule(rule_id) or {}
        sev = self.severity(rule_id, severity)
        score = min(100, SEVERITY_SCORE.get(sev, 45) + score_delta)
        return Finding(
            rule_id=rule_id,
            title=rule.get("title", rule_id),
            severity=sev,
            score=score,
            description=description or rule.get("description", ""),
            evidence=evidence,
            ts=event.ts,
            pid=event.pid,
            comm=event.comm,
            mitre=rule.get("mitre", ""),
            tags=tuple(tags if tags is not None else rule.get("tags", [])),
        )

    # -- allowlist -------------------------------------------------------
    def domain_allowed(self, domain: str) -> bool:
        domain = (domain or "").lower().strip(".")
        if not domain:
            return False
        for allowed in self.allowlist.get("domains", []):
            allowed = allowed.lower().strip(".")
            if domain == allowed or domain.endswith("." + allowed):
                return True
        return False

    def ip_allowed(self, ip: str) -> bool:
        return in_cidrs(ip, self.allowlist.get("cidrs", []))

    def port_allowed(self, port: int) -> bool:
        return port in self.allowlist.get("ports", [])

    def destination_allowed(self, event: Event) -> bool:
        if event.domain and self.domain_allowed(event.domain):
            return True
        if event.dst_ip and self.ip_allowed(event.dst_ip):
            return True
        if event.domain and not event.dst_ip:
            # We only saw a domain (SNI / Host header); domain allowlist decides.
            return False
        return False
