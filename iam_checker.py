#!/usr/bin/env python3
"""IAM policy checker.

Reads AWS IAM policy documents (JSON) and flags risky permissions.
Standard library only. No AWS account needed.

Usage:
    python3 iam_checker.py sample_policies/
    python3 iam_checker.py policy.json --format json --min-severity high
"""

import argparse
import fnmatch
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Actions that let a user give themselves more power. Only flagged when the
# statement applies to every resource ("*"), because a narrow resource limits
# the damage.
PRIVILEGE_ESCALATION_ACTIONS = [
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:UpdateAssumeRolePolicy",
    "iam:AddUserToGroup",
]


@dataclass
class Finding:
    rule: str
    severity: str
    source: str       # file name plus policy number, e.g. admin.json#1
    statement: str    # the Sid, or "Statement[2]"
    message: str


def as_list(value):
    """AWS lets many fields be either one value or a list. Always give a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def find_policy_documents(obj):
    """Find every policy document inside parsed JSON.

    A policy document is any object that has a "Statement" key. This also
    finds documents wrapped in AWS CLI output, such as
    {"PolicyVersion": {"Document": {...}}}.
    """
    found = []
    if isinstance(obj, dict):
        if "Statement" in obj:
            found.append(obj)
        else:
            for value in obj.values():
                found.extend(find_policy_documents(value))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(find_policy_documents(item))
    return found


def is_public_principal(principal):
    """True when a Principal means 'anyone': "*" or {"AWS": "*"}."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return "*" in as_list(principal.get("AWS"))
    return False


def check_statement(stmt, label, source):
    """Return the findings for one policy statement."""
    findings = []

    # Only Allow statements grant power. Deny statements are safe to ignore.
    if stmt.get("Effect") != "Allow":
        return findings

    actions = as_list(stmt.get("Action"))
    resources = as_list(stmt.get("Resource"))
    star_action = "*" in actions
    star_resource = "*" in resources

    def add(rule, severity, message):
        findings.append(Finding(rule, severity, source, label, message))

    if star_action and star_resource:
        add("ADMIN_ACCESS", "critical",
            "Allows every action on every resource (full admin).")
    elif star_action:
        add("WILDCARD_ACTION", "high",
            "Allows every action, limited only by the listed resources.")

    # Service-wide wildcards such as "s3:*" or "iam:*" on every resource.
    iam_wildcard = False
    if star_resource and not star_action:
        for action in actions:
            if isinstance(action, str) and action.endswith(":*"):
                if action.lower() == "iam:*":
                    iam_wildcard = True
                    add("SERVICE_WILDCARD", "high",
                        "iam:* on all resources lets the holder change who has access.")
                else:
                    add("SERVICE_WILDCARD", "medium",
                        f"{action} on all resources is broader than most jobs need.")

    # Actions that can be used to grant more power.
    if star_resource and not star_action and not iam_wildcard:
        matched = [
            risky for risky in PRIVILEGE_ESCALATION_ACTIONS
            if any(fnmatch.fnmatch(risky.lower(), str(a).lower()) for a in actions)
        ]
        if matched:
            shown = ", ".join(matched[:4])
            more = f" and {len(matched) - 4} more" if len(matched) > 4 else ""
            add("PRIVILEGE_ESCALATION", "high",
                f"Can grant more power on all resources: {shown}{more}.")

    # NotAction on Allow means "everything except these". Easy to get wrong.
    if "NotAction" in stmt:
        add("NOT_ACTION_ALLOW", "high",
            "Allow with NotAction grants every action except the ones listed.")

    if "NotResource" in stmt:
        add("NOT_RESOURCE_ALLOW", "medium",
            "Allow with NotResource applies to every resource except the ones listed.")

    # Open to everyone. A Condition (for example one VPC endpoint) is not flagged.
    if is_public_principal(stmt.get("Principal")) and not stmt.get("Condition"):
        add("PUBLIC_PRINCIPAL", "high",
            "Principal is '*', so anyone can use this permission.")

    return findings


def check_document(doc, source):
    findings = []
    for number, stmt in enumerate(as_list(doc.get("Statement"))):
        if not isinstance(stmt, dict):
            continue
        label = stmt.get("Sid") or f"Statement[{number}]"
        findings.extend(check_statement(stmt, label, source))
    return findings


def check_file(path):
    """Check every policy document in one JSON file.

    Returns (findings, number_of_documents).
    """
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    documents = find_policy_documents(data)
    findings = []
    for number, doc in enumerate(documents, start=1):
        findings.extend(check_document(doc, f"{Path(path).name}#{number}"))
    return findings, len(documents)


def collect_paths(inputs):
    """Turn the paths given on the command line into a list of JSON files."""
    paths = []
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            paths.extend(sorted(p.glob("*.json")))
        else:
            paths.append(p)
    return paths


def sort_findings(findings):
    return sorted(findings, key=lambda f: (f.source, -SEVERITY_ORDER[f.severity], f.statement, f.rule))


def format_text(findings, documents):
    lines = []
    for f in findings:
        lines.append(f"[{f.severity.upper():8}] {f.rule:21} {f.source} / {f.statement}")
        lines.append(f"           {f.message}")
    lines.append("")
    lines.append(f"Checked {documents} policy document(s). {len(findings)} finding(s).")
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(description="Flag risky permissions in AWS IAM policies.")
    parser.add_argument("paths", nargs="+", help="policy JSON files or folders")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low",
                        help="hide findings below this level")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high",
                        help="exit with code 1 if any finding is at or above this level")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    all_findings = []
    documents = 0
    for path in collect_paths(args.paths):
        try:
            findings, count = check_file(path)
        except (OSError, json.JSONDecodeError) as error:
            print(f"error: could not read {path}: {error}", file=sys.stderr)
            return 2
        all_findings.extend(findings)
        documents += count

    all_findings = sort_findings(all_findings)
    minimum = SEVERITY_ORDER[args.min_severity]
    shown = [f for f in all_findings if SEVERITY_ORDER[f.severity] >= minimum]

    if args.format == "json":
        print(json.dumps([asdict(f) for f in shown], indent=2))
    else:
        print(format_text(shown, documents))

    threshold = SEVERITY_ORDER[args.fail_on]
    if any(SEVERITY_ORDER[f.severity] >= threshold for f in all_findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
