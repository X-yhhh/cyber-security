"""J1 计数口径回归，仅合成结构，不打开任何 PCAP 或冻结 test。"""
import unittest
import json
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
import j1_audit as audit


def observation(parent, seconds, profile="flow-prefix-v1"):
    return dict(observationId=f"{parent}-{seconds}",parentConnectionId=parent,asOf=f"2026-10-10T00:00:{seconds:02d}Z",
                peerKey="source",servicePort=80,direction="inbound",profile=profile,
                quality={k:False for k in audit.QUALITY}|{"clockSkewMs":None})


class J1AuditTest(unittest.TestCase):
    def test_many_snapshots_of_one_connection_do_not_meet_distinct_requirement(self):
        r=audit.r5([observation("a",1),observation("a",2),observation("a",3)],"dos_slow",2)
        self.assertEqual(r["maxQualityDistinctFlows"],1)
        self.assertEqual(r["qualityQualifiedRatio"],0)

    def test_final_replaces_prefix_and_old_parent_expires(self):
        r=audit.r5([observation("a",1),observation("a",2,"flow-final-v1"),observation("b",13)],"dos_slow",2)
        self.assertEqual(r["maxPrefixDistinctFlows"],1)
        self.assertEqual(r["maxQualityDistinctFlows"],1)
        self.assertEqual(r["clockKnownSnapshots"],0)

    def test_same_time_distinct_connections_count_after_complete_update(self):
        r=audit.r5([observation("a",1),observation("b",1),observation("c",1)],"dos_flood",3)
        self.assertEqual(r["opportunities"],1)
        self.assertEqual(r["maxQualityDistinctFlows"],3)
        self.assertEqual(r["prefixQualifiedRatio"],1)

    def test_same_time_final_replacement_does_not_reuse_old_prefix(self):
        prefix=observation("a",1)
        prefix["snapshotIndex"]=1
        final=observation("a",1,"flow-final-v1")
        final["snapshotIndex"]=2
        r=audit.r5([final,prefix,observation("b",1)],"dos_slow",2)
        self.assertEqual(r["maxQualityDistinctFlows"],2)
        self.assertEqual(r["maxPrefixDistinctFlows"],1)
        self.assertEqual(r["prefixQualifiedRatio"],0)

    def test_selected_low_score_connection_does_not_inherit_other_parent_alert(self):
        a,b=observation("a",1),observation("b",2)
        inference={a["observationId"]:dict(status="succeeded",family="dos_slow",score=.99),b["observationId"]:dict(status="succeeded",family="dos_slow",score=.1)}
        decision=dict(decidedAt="2026-10-10T00:00:02Z",decision="alert",family="dos_slow",source="model",ruleId="",
                      evidence=dict(selectedObservations=[dict(observationId=a["observationId"]),dict(observationId=b["observationId"])]))
        alarms,_=audit.connection_sets([a,b],inference,{},[decision],{"dos_slow":.9})
        self.assertEqual(dict(alarms),{"a":{"dos_slow"}})

    def test_continuous_candidate_decisions_are_not_independent_actions(self):
        first=datetime(2026,10,10,tzinfo=timezone.utc)
        events=[(first+timedelta(seconds=s),"dos_slow","model","") for s in [0,1,9,21,22]]
        self.assertEqual(len(audit.candidate_incidents(events)),2)

    def test_field_comparison_handles_parallel_row_order_but_rejects_changed_features(self):
        a,b=observation("a",1),observation("b",1)
        a["features"]={"packets":3};b["features"]={"packets":8}
        self.assertTrue(audit.observation_fields([a,b],[b,a],timedelta())["identical"])
        altered=dict(b,features={"packets":9})
        result=audit.observation_fields([a,b],[altered,a],timedelta())
        self.assertFalse(result["identical"])
        self.assertEqual(result["mismatches"][0]["fields"],["features"])

    def test_field_comparison_rejects_duplicate_observation_ids(self):
        a=observation("a",1)
        self.assertFalse(audit.observation_fields([a],[a,a],timedelta())["identical"])

    def classification_fixture(self, work, changed_score=False):
        (work/"scenario.json").write_text(json.dumps({"segments":[{"segmentId":"segment"}]}))
        for number in (1,2):
            directory=work/f"round-{number}"/"segment"
            directory.mkdir(parents=True)
            o=observation(f"rotated-parent-{number}",1)
            o["snapshotIndex"]=1
            ledger={"parentConnectionId":o["parentConnectionId"],"First":"2017-01-01T00:00:00Z","Endpoints":[["fixture-host",80],["fixture-peer",12345]]}
            inference={"observationId":o["observationId"],"status":"succeeded","family":"dos_slow","score":.95 if number==2 and changed_score else .9,
                       "familyScores":{"dos_slow":.9},"applicability":"supported","errorCode":None}
            for filename,value in [("offline.jsonl",o),("ledger.jsonl",ledger),("db-inferences.jsonl",inference)]:
                (directory/filename).write_text(json.dumps(value)+"\n")

    def test_classification_reproducibility_aligns_rotated_identity(self):
        with tempfile.TemporaryDirectory() as root:
            work=Path(root);self.classification_fixture(work)
            self.assertTrue(audit.classification_reproducibility(work)["identical"])

    def test_classification_reproducibility_rejects_changed_probability(self):
        with tempfile.TemporaryDirectory() as root:
            work=Path(root);self.classification_fixture(work,True)
            self.assertFalse(audit.classification_reproducibility(work)["identical"])

    def test_unqualified_model_and_other_family_rule_do_not_gain_source_qualification(self):
        closeout={"classEligibility":{
            "dos_flood":{"modelOnly":{"offlineEligible":False},"ruleOnly":{"flood":{"offlineEligible":False}}},
            "port_scan":{"modelOnly":{"offlineEligible":True},"ruleOnly":{"scan":{"offlineEligible":True}}}}}
        self.assertEqual(audit.qualifying_sources(closeout,"dos_flood"),set())
        self.assertEqual(audit.qualifying_sources(closeout,"port_scan"),{("model",""),("rule","scan")})

    def test_report_concurrency_and_wall_time_come_from_actual_run_logs(self):
        with tempfile.TemporaryDirectory() as root:
            work=Path(root);scenario={"segments":[{"segmentId":"port_scan-3","family":"port_scan","observedDurationSeconds":.039}],"normalDurationSeconds":2984.448246}
            (work/"run-stdout.log").write_text("\n".join(json.dumps(v) for v in [
                {"event":"replay_started","round":1,"normalConcurrency":6,"attackConcurrency":1,"speedPerSegment":1},
                {"event":"replay_completed","round":1,"elapsedSeconds":1049}])+"\n")
            config=audit.runtime_configuration(work,scenario);limitations=audit.run_limitations(work,scenario,config)
            self.assertEqual(config["rounds"][0]["attackConcurrency"],1)
            self.assertIsNone(config["rounds"][1]["elapsedSeconds"])
            text="\n".join(limitations)
            self.assertIn("17.48",text);self.assertIn("攻击并发上限 1",text)
            self.assertNotIn("9 分钟",text);self.assertNotIn("中断",text)


if __name__=="__main__":
    unittest.main()
