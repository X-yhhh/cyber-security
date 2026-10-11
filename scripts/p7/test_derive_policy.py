"""双 profile 派生只改版本与接受集合；使用合成策略，不读取真实数据或制品。"""
import copy
import json
from pathlib import Path
import unittest

import compose_policy
import derive_policy


class DerivePolicyTest(unittest.TestCase):
    def setUp(self):
        fixtures = Path(__file__).parent/"testdata"
        self.policy = compose_policy.compose_files(
            fixtures/"candidate-auto.json", fixtures/"policy-preview.json", fixtures/"rules-comparison.json",
            fixtures/"deployment-binding.json", fixtures/"evaluation-plan.json", fixtures/"protection-set.json",
            source_eligibility=fixtures/"source-eligibility.json", evaluated_policy=fixtures/"evaluated-policy.json",
            closeout=fixtures/"p6-closeout.json")
        self.manifest = {"profiles": ["flow-prefix-v1", "flow-final-v1"]}

    def test_deterministic_derivation_preserves_every_numerical_and_deployment_field(self):
        original = copy.deepcopy(self.policy)
        first, record = derive_policy.derive(self.policy, self.manifest, "fixture-derived-v1")
        second, _ = derive_policy.derive(self.policy, self.manifest, "fixture-derived-v1")
        self.assertEqual(first, second)
        self.assertEqual(self.policy, original)
        self.assertEqual(set(record["changedFields"]), {"policyId", "policyVersion", "acceptedProfiles"})
        for key in set(original)-derive_policy.ALLOWED:
            self.assertEqual(first[key], original[key])
        self.assertFalse(record["thresholdsChanged"])

    def test_same_version_and_unsupported_primary_profile_are_rejected(self):
        with self.assertRaises(ValueError):
            derive_policy.derive(self.policy, self.manifest, self.policy["policyVersion"])
        with self.assertRaises(ValueError):
            derive_policy.derive(self.policy, {"profiles": ["flow-final-v1"]}, "fixture-derived-v1")

    def test_accepted_profiles_must_include_primary_profile_in_python_validation(self):
        self.policy["acceptedProfiles"] = ["flow-final-v1"]
        with self.assertRaisesRegex(ValueError, "必须包含主 profile"):
            compose_policy.validate_policy(self.policy)

    def test_duplicate_profiles_and_invalid_source_are_rejected(self):
        with self.assertRaises(ValueError):
            derive_policy.derive(self.policy, {"profiles": ["flow-prefix-v1", "flow-prefix-v1"]}, "fixture-derived-v1")
        self.policy["familyPolicies"][0]["autoThreshold"] = -1
        with self.assertRaises(ValueError):
            derive_policy.derive(self.policy, self.manifest, "fixture-derived-v1")


if __name__ == "__main__":
    unittest.main()
