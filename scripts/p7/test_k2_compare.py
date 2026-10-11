"""K2 对拍必须保留冻结输入和真实并发；只检验边界，不读取回放或测试集。"""
import copy
import unittest
from k2_compare import frozen_inputs


class FrozenInputsTest(unittest.TestCase):
    def scenario(self):
        return dict(modelSha256="model", manifestSha256="manifest", policySha256="policy",
                    policyRawSha256="raw", m1PolicyRawSha256="m1", closeoutSha256="closeout",
                    guardextractSha256="extract", guardreplaydiffSha256="diff", extractorSha256="source",
                    splitManifestSha256="split", splitLedgerSha256="ledger", replayConcurrency=18,
                    attackConcurrency=18, serverThreads=6, segments=["frozen"], speed=1,
                    testRead=False, newFits=0, environment="research")

    def test_binary_rebind_does_not_allow_frozen_inputs_to_drift(self):
        original=self.scenario()
        current=copy.deepcopy(original)
        current["backendSha256"]="optimized"
        frozen_inputs(current,original)
        for key in ("modelSha256","policyRawSha256","extractorSha256","splitLedgerSha256"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                frozen_inputs(dict(current, **{key:"changed"}),original)

    def test_speed_concurrency_and_research_boundary_are_required(self):
        original=self.scenario()
        for key,value in (("speed",2),("attackConcurrency",1),("replayConcurrency",4),
                          ("serverThreads",8),("testRead",True),("newFits",1),("environment","lab"),("maxBatchSize",513)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                frozen_inputs(dict(original, **{key:value}),original)


if __name__ == "__main__":
    unittest.main()
