import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import iam_checker as ic

HERE = Path(__file__).parent


def stmt(**fields):
    """Build one Allow statement. Pass the fields you want to set."""
    base = {"Effect": "Allow"}
    base.update(fields)
    return base


def rules(findings):
    return sorted(f.rule for f in findings)


def check(statement):
    return ic.check_statement(statement, "S", "test.json#1")


class TestRules(unittest.TestCase):
    def test_admin_access(self):
        found = check(stmt(Action="*", Resource="*"))
        self.assertEqual(rules(found), ["ADMIN_ACCESS"])
        self.assertEqual(found[0].severity, "critical")

    def test_wildcard_action_with_specific_resource(self):
        found = check(stmt(Action="*", Resource="arn:aws:s3:::bucket/*"))
        self.assertEqual(rules(found), ["WILDCARD_ACTION"])

    def test_service_wildcard_is_medium(self):
        found = check(stmt(Action="s3:*", Resource="*"))
        self.assertEqual(rules(found), ["SERVICE_WILDCARD"])
        self.assertEqual(found[0].severity, "medium")

    def test_iam_wildcard_is_high_and_not_reported_twice(self):
        found = check(stmt(Action="iam:*", Resource="*"))
        self.assertEqual(rules(found), ["SERVICE_WILDCARD"])
        self.assertEqual(found[0].severity, "high")

    def test_service_wildcard_on_one_resource_is_ok(self):
        self.assertEqual(check(stmt(Action="s3:*", Resource="arn:aws:s3:::one-bucket/*")), [])

    def test_privilege_escalation_action(self):
        found = check(stmt(Action=["iam:PassRole"], Resource="*"))
        self.assertEqual(rules(found), ["PRIVILEGE_ESCALATION"])

    def test_privilege_escalation_matches_partial_wildcards(self):
        found = check(stmt(Action="iam:Put*Policy", Resource="*"))
        self.assertEqual(rules(found), ["PRIVILEGE_ESCALATION"])
        self.assertIn("iam:PutUserPolicy", found[0].message)

    def test_privilege_escalation_ignored_on_one_resource(self):
        self.assertEqual(check(stmt(Action="iam:PassRole", Resource="arn:aws:iam::123456789012:role/app")), [])

    def test_action_names_are_case_insensitive(self):
        found = check(stmt(Action="IAM:passrole", Resource="*"))
        self.assertEqual(rules(found), ["PRIVILEGE_ESCALATION"])

    def test_not_action_allow(self):
        found = check(stmt(NotAction="aws-portal:*", Resource="arn:aws:s3:::b/*"))
        self.assertEqual(rules(found), ["NOT_ACTION_ALLOW"])

    def test_not_resource_allow(self):
        found = check(stmt(Action="s3:GetObject", NotResource="arn:aws:s3:::secret/*"))
        self.assertEqual(rules(found), ["NOT_RESOURCE_ALLOW"])

    def test_public_principal_star(self):
        found = check(stmt(Principal="*", Action="s3:GetObject", Resource="arn:aws:s3:::b/*"))
        self.assertEqual(rules(found), ["PUBLIC_PRINCIPAL"])

    def test_public_principal_aws_star(self):
        found = check(stmt(Principal={"AWS": "*"}, Action="s3:GetObject", Resource="arn:aws:s3:::b/*"))
        self.assertEqual(rules(found), ["PUBLIC_PRINCIPAL"])

    def test_public_principal_with_condition_is_not_flagged(self):
        found = check(stmt(
            Principal="*", Action="s3:GetObject", Resource="arn:aws:s3:::b/*",
            Condition={"StringEquals": {"aws:SourceVpce": "vpce-1"}},
        ))
        self.assertEqual(found, [])

    def test_named_principal_is_not_public(self):
        found = check(stmt(
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Action="s3:GetObject", Resource="arn:aws:s3:::b/*",
        ))
        self.assertEqual(found, [])

    def test_deny_statements_are_ignored(self):
        self.assertEqual(check({"Effect": "Deny", "Action": "*", "Resource": "*"}), [])

    def test_clean_read_only_statement(self):
        found = check(stmt(Action=["s3:GetObject", "s3:ListBucket"], Resource="arn:aws:s3:::logs/*"))
        self.assertEqual(found, [])


class TestDocuments(unittest.TestCase):
    def test_single_statement_object_instead_of_list(self):
        doc = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
        self.assertEqual(rules(ic.check_document(doc, "a.json#1")), ["ADMIN_ACCESS"])

    def test_statement_label_uses_sid_or_position(self):
        doc = {"Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Sid": "Named", "Effect": "Allow", "Action": "*", "Resource": "*"},
        ]}
        labels = [f.statement for f in ic.check_document(doc, "a.json#1")]
        self.assertEqual(labels, ["Statement[0]", "Named"])

    def test_finds_documents_inside_aws_cli_output(self):
        wrapped = {"PolicyVersion": {"Document": {"Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}]}}}
        self.assertEqual(len(ic.find_policy_documents(wrapped)), 1)

    def test_finds_several_documents_in_one_file(self):
        many = [{"Statement": []}, {"Statement": []}]
        self.assertEqual(len(ic.find_policy_documents(many)), 2)

    def test_json_without_policies_gives_nothing(self):
        self.assertEqual(ic.find_policy_documents({"hello": "world"}), [])


class TestSampleFiles(unittest.TestCase):
    def setUp(self):
        self.paths = ic.collect_paths([str(HERE / "sample_policies")])

    def test_sample_folder_has_six_files(self):
        self.assertEqual(len(self.paths), 6)

    def test_sample_folder_gives_six_findings(self):
        total = []
        for path in self.paths:
            findings, _ = ic.check_file(path)
            total.extend(findings)
        self.assertEqual(len(total), 6)

    def test_clean_samples_have_no_findings(self):
        for name in ("05_read_only_clean.json", "06_public_but_limited_clean.json"):
            findings, count = ic.check_file(HERE / "sample_policies" / name)
            self.assertEqual((findings, count), ([], 1), name)


class TestCommandLine(unittest.TestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ic.main(argv)
        return code, out.getvalue(), err.getvalue()

    def sample(self):
        return str(HERE / "sample_policies")

    def test_exit_code_1_when_findings_reach_fail_on(self):
        code, _, _ = self.run_main([self.sample()])
        self.assertEqual(code, 1)

    def test_exit_code_0_when_only_clean_files(self):
        clean = str(HERE / "sample_policies" / "05_read_only_clean.json")
        code, _, _ = self.run_main([clean])
        self.assertEqual(code, 0)

    def test_fail_on_critical_ignores_high_findings(self):
        high_only = str(HERE / "sample_policies" / "03_bucket_open_to_world.json")
        code, _, _ = self.run_main([high_only, "--fail-on", "critical"])
        self.assertEqual(code, 0)

    def test_json_output_is_valid(self):
        _, out, _ = self.run_main([self.sample(), "--format", "json"])
        data = json.loads(out)
        self.assertEqual(len(data), 6)
        self.assertEqual({"rule", "severity", "source", "statement", "message"}, set(data[0]))

    def test_min_severity_hides_lower_findings(self):
        _, out, _ = self.run_main([self.sample(), "--format", "json", "--min-severity", "critical"])
        self.assertEqual([f["rule"] for f in json.loads(out)], ["ADMIN_ACCESS"])

    def test_missing_file_gives_exit_code_2(self):
        code, _, err = self.run_main(["does_not_exist.json"])
        self.assertEqual(code, 2)
        self.assertIn("could not read", err)

    def test_broken_json_gives_exit_code_2(self):
        with tempfile.TemporaryDirectory() as folder:
            bad = os.path.join(folder, "bad.json")
            with open(bad, "w", encoding="utf-8") as handle:
                handle.write("{ not json")
            code, _, _ = self.run_main([bad])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
