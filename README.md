# IAM Policy Checker

A small, readable tool that reads AWS IAM policy files (JSON) and flags risky permissions. Standard library only, no cloud account needed.

## What it does

IAM policies decide who can do what in an AWS account. A policy that is too broad is a common way for a small mistake to become a big problem. This tool reads policy files, looks at every statement that grants access, and checks it against seven rules: full admin access, wildcard actions, service-wide wildcards, ways to give yourself more power, "everything except" rules, and permissions open to anyone.

## Run it

```bash
python3 iam_checker.py sample_policies/
```

More options:

```bash
python3 iam_checker.py policy.json --format json          # machine-readable output
python3 iam_checker.py sample_policies/ --min-severity high   # hide low and medium findings
python3 iam_checker.py a.json b.json --fail-on critical   # only exit 1 for critical findings
```

You can give it files, folders (it reads every `.json` file in them), or both.

The exit code is `1` when any finding is at or above `--fail-on` (default `high`), `0` when there are none, and `2` when a file can't be read. That makes it easy to use as a check in a script or CI job.

It also finds policies inside the output of AWS CLI commands such as `aws iam get-policy-version`, so you can save that output to a file and check it directly.

## Rules

| Rule | Severity | Fires when |
|------|----------|------------|
| `ADMIN_ACCESS` | critical | `Action` is `*` and `Resource` is `*` |
| `WILDCARD_ACTION` | high | `Action` is `*`, limited only by the listed resources |
| `SERVICE_WILDCARD` | high / medium | `iam:*` on all resources (high), or another `service:*` on all resources (medium) |
| `PRIVILEGE_ESCALATION` | high | On all resources, an action that can grant more power, such as `iam:PassRole` or `iam:AttachUserPolicy` |
| `NOT_ACTION_ALLOW` | high | An Allow statement uses `NotAction`, which grants everything except the listed actions |
| `NOT_RESOURCE_ALLOW` | medium | An Allow statement uses `NotResource`, which applies to everything except the listed resources |
| `PUBLIC_PRINCIPAL` | high | `Principal` is `*` (anyone), with no `Condition` |

## Choices to avoid false alarms

- Only `Allow` statements are checked. A `Deny` statement can only take power away.
- Escalation actions and service wildcards are only flagged when the resource is `*`. The same action on one named resource is far less dangerous.
- A public principal with a `Condition` attached, such as one limited to a VPC endpoint, is not flagged.
- Action names are matched without caring about upper or lower case, and partial wildcards such as `iam:Put*Policy` are expanded.
- `iam:*` is reported once as a service wildcard, not again as an escalation.

## Example output

The sample folder has six policies. Four have problems and two are clean.

```
[CRITICAL] ADMIN_ACCESS          01_admin_everything.json#1 / EverythingAllowed
           Allows every action on every resource (full admin).
[HIGH    ] PRIVILEGE_ESCALATION  02_developer_can_grant_power.json#1 / DeveloperAccess
           Can grant more power on all resources: iam:PassRole, iam:AttachUserPolicy.
[HIGH    ] SERVICE_WILDCARD      02_developer_can_grant_power.json#1 / ManageIdentity
           iam:* on all resources lets the holder change who has access.
[MEDIUM  ] SERVICE_WILDCARD      02_developer_can_grant_power.json#1 / DeveloperAccess
           s3:* on all resources is broader than most jobs need.
[HIGH    ] PUBLIC_PRINCIPAL      03_bucket_open_to_world.json#1 / PublicRead
           Principal is '*', so anyone can use this permission.
[HIGH    ] NOT_ACTION_ALLOW      04_everything_except.json#1 / AllButBilling
           Allow with NotAction grants every action except the ones listed.

Checked 6 policy document(s). 6 finding(s).
```

## Test it

```bash
python3 -m unittest -v
```

32 tests cover each rule, the clean cases, the different ways AWS writes a policy (one statement or a list, one value or a list), the sample files, and the exit codes.

## How I built it

This is part of a 30-day challenge to learn cloud security by building in public. It follows the [log detector](https://github.com/twistedsol/log-detector) and the [misconfiguration scan](https://github.com/twistedsol/misconfig-scan). I wrote the code together with Claude. No AWS account or card is needed, so everything here runs on my own computer.

## Limits

- It checks each statement on its own. It does not work out the combined effect of several policies attached to one user.
- It reads the policy text only. It does not know which users or roles the policy is attached to.
- The list of escalation actions is short and covers the well-known IAM ones. It is not a complete list.
- It only understands AWS IAM policy JSON.

## Next ideas

- Add a rule for `sts:AssumeRole` trust policies that trust any account
- Check policies attached to real roles using the AWS CLI output (the AWS lab, later)
- Output a markdown report
