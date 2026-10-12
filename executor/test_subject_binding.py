"""运行前绑定必须覆盖实际执行配置，不能把旧 P5 结果追认给另一个发布组合。"""
import copy
import unittest
from .common import digest, Rejected
from .subject_binding import validate, verify_config


class SubjectBindingTest(unittest.TestCase):
    def setUp(self):
        self.subject=dict(contractVersion='host-guard/5.0.0-rc.3',protocolVersions={},
                          modelId='model',manifestSha256='a'*64,policyId='policy',policySha256='b'*64,
                          featureProfileSha256='c'*64,extractorSha256='d'*64,
                          evaluationPlanSha256='e'*64,capabilityIds=['cap-a','cap-b'],environment='lab')
        self.binding=dict(bundleId='11111111-1111-4111-8111-111111111111',subject=self.subject,
                          subjectSha256=digest(self.subject))
        self.config=dict(environment='lab',bundleIds=[self.binding['bundleId']],
                         policyHashes=[self.subject['policySha256']],capabilityIds=['cap-a'])

    def test_runtime_is_bound_before_execution(self):
        result=verify_config(self.binding,self.config)
        self.assertTrue(result['verifiedBeforeExecution'])
        self.assertEqual(result['subjectSha256'],digest(self.subject))

    def test_changed_subject_and_hash_only_are_rejected(self):
        changed=copy.deepcopy(self.binding);changed['subject']['policySha256']='f'*64
        with self.assertRaises(Rejected):validate(changed)
        with self.assertRaises(Rejected):validate({'subjectSha256':digest(self.subject)})

    def test_wrong_or_extra_runtime_authority_is_rejected(self):
        for field,value in [('environment','research'),('bundleIds',[]),
                            ('bundleIds',[self.binding['bundleId'],'another']),
                            ('policyHashes',['f'*64]),('capabilityIds',[]),('capabilityIds',['other'])]:
            with self.subTest(field=field,value=value),self.assertRaises(Rejected):
                verify_config(self.binding,dict(self.config,**{field:value}))

    def test_capability_order_duplicates_and_binding_uuid_are_validated(self):
        for caps in (['cap-b','cap-a'],['cap-a','cap-a'],[]):
            value=copy.deepcopy(self.binding);value['subject']['capabilityIds']=caps
            value['subjectSha256']=digest(value['subject'])
            with self.assertRaises(Rejected):validate(value)
        with self.assertRaises(Rejected):validate(dict(self.binding,bundleId='not-a-uuid'))


if __name__=='__main__':unittest.main()
