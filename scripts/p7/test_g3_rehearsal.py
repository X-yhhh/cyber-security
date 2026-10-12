"""门禁反例覆盖：每类每来源、时钟、正常段、独立执行观察与关联不能缺省通过。"""
import copy
from datetime import datetime, timezone, timedelta
import unittest
import tempfile
import json
from pathlib import Path
from scripts.p7.g3_rehearsal import gate, GateError, evaluate_directory


class G3RehearsalTest(unittest.TestCase):
    def setUp(self):
        at=datetime(2030,1,1,tzinfo=timezone.utc)
        iso=lambda seconds:(at+timedelta(seconds=seconds)).isoformat().replace('+00:00','Z')
        rows=[];replays=[];decisions=[]
        for family,count in [('port_scan',3),('brute_force',3),('dos_flood',3),('dos_slow',3),('normal',6)]:
            for i in range(count):
                sid=f'{family}-{i+1}';end=600 if family=='normal' else 100
                rows.append(dict(scenarioId=sid,family=family,captureStart=iso(-30),sourceStart=iso(0),sourceEnd=iso(end),pcapSha256='a'*64))
                replays.append(dict(scenarioId=sid,speed=1,timeOffsetMicros=0,pcapSha256='a'*64,packets=10,wallStartedAt=iso(-30),wallFinishedAt=iso(end)))
                if family in ('port_scan','brute_force','dos_slow'):
                    for source in ('model','rule') if family=='port_scan' else ('model',):
                        proof=dict(family=family,source=source,ruleId='scan-ports' if source=='rule' else '',reasonCode='CAPABILITY_NOT_SUPPORTED',
                                   hypothetical=dict(decision='block_candidate',distinctParents=5,reasonCode=None,actionable=False))
                        decisions.append(dict(id=sid+source,scenarioId=sid,decidedAt=iso(5),evidence=proof))
        state=dict(mode='rehearse',evidenceKind='synthetic',captureComplete=True,reportImported=True,
                   manifest=dict(contractVersion='host-guard-lab/1.1',time=dict(scenarioOffsets={r['scenarioId']:0 for r in rows})))
        runtime=dict(realBackend=True,realSensor=True,speed=1,realPF=False,packetInjection=False)
        sub=[dict(kind='observation',at=iso(i),installedRules=[],commandIds=[]) for i in range(-40,602,2)]
        sub.append(dict(kind='stopped',at=iso(602),installedRules=[]))
        self.values=[state,runtime,rows,dict(replays=replays),decisions,dict(unlinkedCommandIds=[],unlinkedDecisionIds=[]),sub,{'table':'hash'},{'table':'hash'}]
    def test_complete_evidence_passes_as_synthetic_only(self):
        result=gate(*self.values);self.assertTrue(result['passed']);self.assertFalse(result['formalG3Eligible'])
        self.assertEqual(result['normal']['alertsPerHour'],0)
        stages=result['scenarioTrace'][0]
        self.assertEqual(stages['firstRejectionStages']['T1'],0)
        self.assertEqual(stages['deploymentFirstRejectionStages']['T1'],1)
    def test_every_scan_source_is_required(self):
        self.values[4]=[d for d in self.values[4] if d['evidence']['source']!='rule']
        self.assertFalse(gate(*self.values)['passed'])
    def test_late_candidate_or_insufficient_slow_parents_fails(self):
        self.values[4][0]['decidedAt']='2030-01-01T00:00:11Z';self.assertFalse(gate(*self.values)['passed'])
        self.setUp()
        for d in self.values[4]:
            if d['evidence']['family']=='dos_slow':d['evidence']['hypothetical']['distinctParents']=4
        self.assertFalse(gate(*self.values)['passed'])
    def test_normal_candidate_is_never_hidden(self):
        d=copy.deepcopy(self.values[4][0]);d['scenarioId']='normal-1';self.values[4].append(d)
        result=gate(*self.values);self.assertFalse(result['passed']);self.assertEqual(result['normal']['candidateCount'],1)
    def test_every_normal_scenario_covers_the_attack_windows(self):
        normal=next(r for r in self.values[2] if r['family']=='normal')
        normal['sourceEnd']='2030-01-01T00:00:10Z'
        result=gate(*self.values)
        self.assertFalse(result['normalAlwaysConcurrent'])
        self.assertFalse(result['passed'])
    def test_missing_or_unlinked_facts_fail_closed(self):
        self.values[5]['unlinkedDecisionIds']=['missing'];self.assertFalse(gate(*self.values)['passed'])
        self.values[5]={};self.assertFalse(gate(*self.values)['passed'])
    def test_substitute_observation_gap_and_live_rule_fail(self):
        self.values[6]=self.values[6][-2:];self.assertFalse(gate(*self.values)['passed'])
        self.setUp();self.values[6][0]['installedRules']=['unremoved'];self.assertFalse(gate(*self.values)['passed'])
    def test_final_empty_inventory_covers_capture_between_polls(self):
        self.values[6]=[r for r in self.values[6] if r['kind']=='stopped' or r['at']<'2030-01-01T00:09:50Z']
        self.assertTrue(gate(*self.values)['cleanup']['coversReplay'])
    def test_speed_offset_and_database_mutation_fail(self):
        self.values[3]['replays'][0]['speed']=2;self.assertFalse(gate(*self.values)['passed'])
        self.setUp();self.values[8]={'table':'modified'};self.assertFalse(gate(*self.values)['passed'])
    def test_truncated_scenario_set_is_rejected(self):
        self.values[2].pop()
        with self.assertRaises(GateError):gate(*self.values)
    def test_failed_attempt_retains_diagnostic_without_model_conclusion(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)
            (path/'failure.json').write_text(json.dumps(dict(code='LAB_SENSOR_FAILED')))
            for name in ('business-before.json','business-after.json'):
                (path/name).write_text(json.dumps(dict(table='same')))
            result=evaluate_directory(path)
            self.assertFalse(result['passed'])
            self.assertTrue(result['businessDatabaseUnchanged'])
            self.assertEqual(result['failure']['code'],'LAB_SENSOR_FAILED')
            self.assertIn('sensor-report.json',result['missingEvidence'])
            self.assertTrue(all(r['status']=='not_evaluated' for r in result['classes']))


if __name__=='__main__':unittest.main()
