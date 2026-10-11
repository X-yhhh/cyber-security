package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** T2：消费、推理、对象 episode、完整决策及动作预留同一事务；重复消息不重复推理/动作。 */
@Service
public class GuardDetection {
    private final GuardStore store;private final GuardMapper mapper;private final GuardModelRuntime runtime;private final GuardBudget budget;
    private final GuardCases cases;private final GuardHealth health;private final GuardEligibility eligibility;private final GuardActions actions;
    /** 只缓存不可变观察内容；每批最新性/投影/推理状态仍从数据库读取，摘要改变时不复用。 */
    private record ObservationContent(String hash,JsonNode value){}
    private final Map<Long,ObservationContent> observationContents=new LinkedHashMap<>(256,.75f,true);
    private synchronized void remember(long id,String hash,JsonNode value){
        observationContents.put(id,new ObservationContent(hash,value));
        while(observationContents.size()>10000)observationContents.remove(observationContents.keySet().iterator().next());
    }
    private synchronized JsonNode recalled(long id,String hash){var cached=observationContents.get(id);return cached!=null&&Objects.equals(hash,cached.hash())?cached.value():null;}
    public GuardDetection(GuardStore store,GuardMapper mapper,GuardModelRuntime runtime,GuardBudget budget,GuardHealth health,GuardEligibility eligibility,GuardActions actions,GuardCases cases){this.store=store;this.mapper=mapper;this.runtime=runtime;this.budget=budget;this.health=health;this.eligibility=eligibility;this.actions=actions;this.cases=cases;}
    @Transactional public void consume(String eventKey,String topic,JsonNode payload){
        uuid(eventKey);Map<String,Object> batch=null;
        if(topic.equals("guard.observation.accepted")){fields(payload,"batchId","");batch=store.external("guard_observation_batch",uuid(payload,"batchId"),false);store.lockAsset(number(batch,"asset_id"));}
        var prior=store.one("consumed_message",map("consumer","guard-v5","message_key",eventKey),true);if(prior!=null&&"consumed".equals(str(prior,"status")))return;
        if(prior==null)prior=store.insert("consumed_message",map("consumer","guard-v5","message_key",eventKey,"status","processing"));
        if(batch!=null){var binding=store.one("guard_asset_binding",map("asset_id",batch.get("asset_id"),"status","active"),false);
            if(binding!=null){var bundle=store.get("guard_release_bundle",number(binding,"bundle_id"));var model=store.get("guard_model",number(bundle,"model_id"));
                var observations=new ArrayList<>(store.rows("guard_observation",map("batch_id",batch.get("id")),false,GuardContracts.MAX_BATCH_SIZE));observations.sort(Comparator.comparing(r->instant(r.get("as_of"))));
                List<Scored> scored=scoreBatch(observations,model);
                correlate(scored,bundle,binding,null);
            }
        }
        store.update("consumed_message",number(prior,"id"),map("status","consumed","consumed_at",db(store.now())));
    }
    /** 已推理的观察及其不可变推理事实。 */
    public record Scored(Map<String,Object> observation,Map<String,Object> inference){}
    /** 同一已锁资产事务内推理；已有事实跳过，逐快照结果不变，多行回填主键后才进入证据投影。 */
    public List<Scored> scoreBatch(List<Map<String,Object>> observations,Map<String,Object> model){
        if(observations.isEmpty())return List.of();
        var existing=new HashSet<Long>();for(var row:store.byKeys("guard_inference",observations.stream().map(o->map("observation_id",o.get("id"),"model_id",model.get("id"))).toList(),false))existing.add(number(row,"observation_id"));
        var scored=new ArrayList<Scored>();var facts=new ArrayList<Map<String,Object>>();
        JsonNode manifest=json(model,"manifest_json");
        try(var phase=GuardBatchProfile.phase("inference_and_persistence")){
            Instant batchStartedAt=store.now();
            for(var o:observations){if(existing.contains(number(o,"id")))continue;
                JsonNode payload=json(o,"payload_json");remember(number(o,"id"),str(o,"content_sha256"),payload);
                var result=runtime.infer(model,payload,batchStartedAt,manifest);
                var fact=map("observation_id",o.get("id"),"asset_id",o.get("asset_id"),"model_id",model.get("id"),"status",result.status(),"score",result.score(),"family",result.family(),"family_scores_json",result.familyScores().isEmpty()?null:canonical(node(result.familyScores())),"applicability",result.applicability(),"manifest_sha256",model.get("manifest_sha256"),"error_code",result.error());
                facts.add(fact);scored.add(new Scored(o,fact));}
            if(!facts.isEmpty()){
                // 用全部推理完成后的数据库时刻作为每条完成时间的保守上界；不逐条往返，也不回推或提前计时。
                LocalDateTime completedAt=db(store.now());for(var fact:facts)fact.put("completed_at",completedAt);
                store.addAllReturning("guard_inference",facts);
            }
        }return scored;
    }
    /** 本批触及的 episode 路径；trigger 为该路径本批最后到达（按 asOf 排序）的最新快照。 */
    private record Touch(Map<String,Object> episode,Map<String,Object> trigger,String family,String source,String ruleId,String scope,List<JsonNode> selections){}
    /** 最新观察的一条来源路径；组合键只读，不能把回填主键的可变插入行用作 HashMap 键。 */
    private record Stage(Map<String,Object> key,Map<String,Object> observation,Map<String,Object> inference,String family,String source,String ruleId,String scope,boolean matched,boolean create){}
    /** 模型类别与每条规则独立成桶；未命中事实也保留，降分和改类覆盖旧投影。 */
    public JsonNode correlate(Map<String,Object> observation,Map<String,Object> inference,Map<String,Object> bundle,Map<String,Object> binding){return correlate(observation,inference,bundle,binding,null);}
    /** J1 研究旁路追加不可执行的准备度证明，正式绑定仍走原有门禁。 */
    public JsonNode correlate(Map<String,Object> observation,Map<String,Object> inference,Map<String,Object> bundle,Map<String,Object> binding,JsonNode hypotheticalPolicy){
        return correlate(List.of(new Scored(observation,inference)),bundle,binding,hypotheticalPolicy);
    }
    /**
     * 一个观察批次的 T2：逐条写规则事实并更新各路径的最新证据投影，批末对每个被触及的 episode 只判定一次。
     * 判定只使用截至批末已到达的证据（契约 8.0），同批被新快照取代的旧快照不参与；决策数随批次而非观察数增长，
     * 避免大 episode 中每条观察都重读并复制全部证据。
     */
    public JsonNode correlate(List<Scored> batch,Map<String,Object> bundle,Map<String,Object> binding,JsonNode hypotheticalPolicy){
        var p=store.get("guard_decision_policy",number(bundle,"policy_id"));JsonNode policy=json(p,"definition_json");JsonNode result=object("decision","observe");
        if(batch.isEmpty())return result;
        // 先按固定顺序持有资产锁，再批量读取最新性/episode/projection；与原逐条路径保留同一事务和因果排序。
        var memo=new HashMap<List<Object>,Object>();
        batch.stream().map(s->number(s.observation(),"asset_id")).distinct().sorted().forEach(aid->memo.put(List.of("asset",aid),store.lockAsset(aid)));
        var latest=mapper.latestObservationIds(batch.stream().map(s->number(s.observation(),"id")).toList());
        Map<Long,Touch> touched=new LinkedHashMap<>();List<Map<String,Object>> ruleFacts=new ArrayList<>();List<Stage> stages=new ArrayList<>();
        for(var item:batch){
            var observation=item.observation();var inference=item.inference();JsonNode o=recalled(number(observation,"id"),str(observation,"content_sha256"));
            if(o==null)o=json(observation,"payload_json");
            remember(number(observation,"id"),str(observation,"content_sha256"),o);
            require(hypotheticalPolicy==null||(binding==null&&"research".equals(o.path("environment").asText())),"REPLAY_REAL_TARGET_FORBIDDEN");
            boolean current=latest.contains(number(observation,"id"));
            for(JsonNode fp:policy.path("familyPolicies")){
                String family=fp.path("family").asText();if(current)stages.add(path(observation,o,inference,bundle,policy,family,"model","",false,family.equals(str(inference,"family"))));
            }
            for(JsonNode rule:policy.path("rulePolicies")){
                var evaluation=GuardRules.evaluate(rule,o);String ruleId=rule.path("ruleId").asText(),family=rule.path("family").asText();
                ruleFacts.add(map("asset_id",observation.get("asset_id"),"observation_id",observation.get("id"),"policy_id",bundle.get("policy_id"),"rule_version","host-guard-rules/1","rule_id",ruleId,"family",family,"matched",evaluation.matched(),"applicable",evaluation.applicable(),"payload_json",canonical(object("rule",rule,"value",evaluation.value(),"asOf",o.get("asOf"),"matched",evaluation.matched(),"applicable",evaluation.applicable()))));
                if(current)stages.add(path(observation,o,inference,bundle,policy,family,"rule",ruleId,evaluation.matched(),evaluation.matched()));
            }
        }
        if(!ruleFacts.isEmpty())store.addAll("guard_rule_evaluation",ruleFacts);
        try(var phase=GuardBatchProfile.phase("evidence_projection")){project(stages,touched);}
        var evidenceByEpisode=new HashMap<Long,List<Map<String,Object>>>();
        var episodeIds=new ArrayList<>(touched.keySet());
        try(var phase=GuardBatchProfile.phase("evidence_read")){
            for(int i=0;i<episodeIds.size();i+=500)for(var row:mapper.episodesEvidence(episodeIds.subList(i,Math.min(i+500,episodeIds.size()))))
                evidenceByEpisode.computeIfAbsent(number(row,"episode_id"),k->new ArrayList<>()).add(row);
            // MySQL 只排序窄主键，再回读 JSON；避免携带整份观察的窗口排序写入临时表。
            evidenceByEpisode.values().forEach(rows->rows.sort(Comparator.comparingLong((Map<String,Object> r)->number(r,"id")).reversed()));
            var content=new HashMap<Long,JsonNode>();var missing=new LinkedHashMap<Long,Map<String,Object>>();
            for(var rows:evidenceByEpisode.values())for(var row:rows){long oid=number(row,"observation_id");JsonNode cached=recalled(oid,str(row,"observation_content_sha256"));
                if(cached==null)missing.putIfAbsent(oid,map("id",oid));else content.put(oid,cached);}
            for(var row:store.byKeys("guard_observation",new ArrayList<>(missing.values()),false)){
                JsonNode value=json(row,"payload_json");long oid=number(row,"id");remember(oid,str(row,"content_sha256"),value);content.put(oid,value);}
            for(var rows:evidenceByEpisode.values())for(var row:rows){JsonNode value=content.get(number(row,"observation_id"));require(value!=null,"RESOURCE_NOT_FOUND");row.put("observation_node",value);}
        }
        // research 已明示无执行路径，可在同一事务批量落库；真实动作仍逐项预留预算，保持动作间依赖。
        List<Map<String,Object>> deferred=hypotheticalPolicy==null?null:new ArrayList<>();
        // 批内只读事实（模型、健康窗口、批次连续性、匹配能力）在同一事务中不变，按键复用，避免每个 episode 重复查询。
        try(var phase=GuardBatchProfile.phase("evidence_audit")){
            store.auditSystemAll("guard.episode.evidence_selected",touched.values().stream().map(t->new GuardStore.AuditProof(str(t.episode(),"public_id"),number(t.episode(),"asset_id"),JSON.createObjectNode().set("selections",JSON.createArrayNode().addAll(t.selections())))).toList());
        }
        // 研究批次没有动作间依赖，以投影完成后的数据库时刻共同判定；正式路径仍逐项读取当前时间。
        Instant batchDecisionAt=hypotheticalPolicy==null?null:store.now();
        try(var phase=GuardBatchProfile.phase("episode_decision")){for(var touch:touched.values()){
            // 证据选择审计按 episode 每批一条，按到达顺序列出本批全部选中与被替换的快照。
            result=decide(touch,bundle,binding,p,policy,hypotheticalPolicy,memo,evidenceByEpisode.getOrDefault(number(touch.episode(),"id"),List.of()),deferred,batchDecisionAt);}
            if(deferred!=null&&!deferred.isEmpty()){
                store.addAllReturning("guard_decision",deferred);
                var episodes=new HashMap<Long,Map<String,Object>>();for(var touch:touched.values())episodes.put(number(touch.episode(),"id"),touch.episode());
                cases.detectedBatch(episodes,deferred);
                store.updateAll("guard_episode",episodes.values().stream().map(e->map("id",e.get("id"),"revision",number(e,"revision")+1)).toList());
                store.insertAll("outbox_event",deferred.stream().map(d->map("event_key",id(),"aggregate_type","guard","aggregate_id",d.get("public_id"),"topic","guard.decision.recorded","payload_json",canonical(object("decisionId",d.get("public_id"))),"status","pending")).toList());
            }}
        return result;
    }
    /** 组合键与处置作用域保持原语义；此处不查询或创建数据库事实。 */
    private Stage path(Map<String,Object> observation,JsonNode o,Map<String,Object> inference,Map<String,Object> bundle,JsonNode policy,String family,String detectionSource,String ruleId,boolean matched,boolean create){
        long aid=number(observation,"asset_id");String scope=GuardDecisionEngine.familyPolicy(policy,family).path("scope").asText("peer_service");
        // 出站扫描只能按原服务记录告警；不能创建仅允许入站的全端口处置作用域。
        if(scope.equals("peer_inbound")&&!"inbound".equals(str(observation,"direction")))scope="peer_service";
        Object servicePort=scope.equals("peer_inbound")?null:observation.get("service_port");if(servicePort==null&&!scope.equals("peer_inbound"))servicePort=0;
        var key=map("asset_id",aid,"sensor_id",observation.get("sensor_id"),"boot_id",observation.get("boot_id"),"peer_key",observation.get("peer_key"),"key_epoch",observation.get("key_epoch"),"direction",observation.get("direction"),"transport",observation.get("transport"),"service_port",servicePort,"family",family,"scope",scope,"source",detectionSource,"rule_id",ruleId,"bundle_id",bundle.get("id"),"bucket_start",db(Instant.ofEpochSecond(time(o,"asOf").getEpochSecond()/30*30)));
        return new Stage(Collections.unmodifiableMap(columns(key,key.keySet())),observation,inference,family,detectionSource,ruleId,scope,matched,create);
    }
    /** SQL 等值组合键归一化：JDBC 的 unsigned BIGINT/生成键可分别为 BigInteger/Long，DATETIME 也可为 Timestamp。 */
    private static Map<String,Object> columns(Map<String,Object> row,Set<String> columns){var result=new LinkedHashMap<String,Object>();for(String key:columns){Object v=row.get(key);result.put(key,v instanceof Number n?n.longValue():v instanceof java.util.Date d?db(d.toInstant()):v);}return result;}
    private static Map<String,Object> evidenceKey(Stage stage,Map<String,Object> episode){return map("episode_id",number(episode,"id"),"parent_connection_id",stage.observation().get("parent_connection_id"),"source",stage.source(),"rule_id",stage.ruleId());}
    /** 批量锁定有限组合键，严格新增 episode 与证据；降分/改类仍替换全部已存在路径，不能只处理命中路径。 */
    private void project(List<Stage> stages,Map<Long,Touch> touched){
        if(stages.isEmpty())return;
        var keys=stages.stream().map(Stage::key).distinct().toList();var lookups=new ArrayList<Map<String,Object>>();
        for(var key:keys){var lookup=new LinkedHashMap<>(key);Object port=lookup.remove("service_port");lookup.put("service_port_key",port==null?0:port);lookups.add(lookup);}
        var episodes=new HashMap<Map<String,Object>,Map<String,Object>>();
        try(var phase=GuardBatchProfile.phase("episode_lookup")){for(var row:store.byKeys("guard_episode",lookups,true))episodes.put(columns(row,keys.getFirst().keySet()),row);}
        var inserts=new LinkedHashMap<Map<String,Object>,Map<String,Object>>();
        for(var stage:stages)if(stage.create()&&!episodes.containsKey(stage.key()))inserts.computeIfAbsent(stage.key(),k->{var row=new LinkedHashMap<>(k);row.put("revision",1L);return row;});
        try(var phase=GuardBatchProfile.phase("episode_insert")){if(!inserts.isEmpty()){store.addAllReturning("guard_episode",new ArrayList<>(inserts.values()));episodes.putAll(inserts);}}
        var evidenceKeys=stages.stream().filter(s->episodes.containsKey(s.key())&&!inserts.containsKey(s.key())).map(s->evidenceKey(s,episodes.get(s.key()))).distinct().toList();
        var priorEvidence=new HashMap<Map<String,Object>,Map<String,Object>>();
        try(var phase=GuardBatchProfile.phase("evidence_lookup")){for(var row:store.evidenceKeys(evidenceKeys))priorEvidence.put(columns(row,evidenceKeys.getFirst().keySet()),row);}
        var addedEvidence=new ArrayList<Map<String,Object>>();
        for(var stage:stages){var episode=episodes.get(stage.key());if(episode==null)continue;
            stage(touched,stage,episode,priorEvidence.get(evidenceKey(stage,episode)),addedEvidence);}
        try(var phase=GuardBatchProfile.phase("evidence_write")){if(!addedEvidence.isEmpty())store.addAll("guard_episode_evidence",addedEvidence);}
    }
    /** 更新 parent 最新投影，审计引用原观察 UUID；新增事实在批末统一写入，再进入判定。 */
    private void stage(Map<Long,Touch> touched,Stage stage,Map<String,Object> episode,Map<String,Object> prev,List<Map<String,Object>> addedEvidence){
        var observation=stage.observation();var inference=stage.inference();String detectionSource=stage.source(),ruleId=stage.ruleId(),family=stage.family();boolean matched=stage.matched();
        var values=map("episode_id",episode.get("id"),"parent_connection_id",observation.get("parent_connection_id"),"observation_id",observation.get("id"),"inference_id",inference.get("id"),"score",detectionSource.equals("model")?inference.get("score"):null,"family",detectionSource.equals("model")?inference.get("family"):family,"source",detectionSource,"rule_id",ruleId,"rule_matched",matched,"family_scores_json",detectionSource.equals("model")?inference.get("family_scores_json"):null,"as_of",observation.get("as_of"));
        if(prev==null)addedEvidence.add(values);else store.update("guard_episode_evidence",number(prev,"id"),values);
        var selection=object("observationId",observation.get("public_id"),"source",detectionSource,"ruleId",ruleId,"replacedObservationId",prev==null?null:prev.get("observation_public_id"));
        var prior=touched.get(number(episode,"id"));var selections=prior==null?new ArrayList<JsonNode>():prior.selections();selections.add(selection);
        touched.put(number(episode,"id"),new Touch(episode,observation,family,detectionSource,ruleId,stage.scope(),selections));
    }
    /** 对一个 episode 按 T1—T9 判定一次；目标、预算与授权按 trigger 及全部选定证据逐条复核。 */
    @SuppressWarnings("unchecked")
    private static <T> T memo(Map<List<Object>,Object> memo,List<Object> key,java.util.function.Supplier<T> load){
        if(memo.containsKey(key))return (T)memo.get(key);T value=load.get();memo.put(key,value);return value;}
    private JsonNode decide(Touch touch,Map<String,Object> bundle,Map<String,Object> binding,Map<String,Object> p,JsonNode policy,JsonNode hypotheticalPolicy,Map<List<Object>,Object> cache,List<Map<String,Object>> selectedEvidence,List<Map<String,Object>> deferred,Instant batchDecisionAt){
        var observation=touch.trigger();var episode=touch.episode();String family=touch.family(),detectionSource=touch.source(),ruleId=touch.ruleId(),scope=touch.scope();
        long aid=number(observation,"asset_id");Map<String,Object> asset=memo(cache,List.of("asset",aid),()->store.lockAsset(aid));
        JsonNode remembered=recalled(number(observation,"id"),str(observation,"content_sha256"));
        JsonNode o=remembered==null?json(observation,"payload_json"):remembered;Instant now=batchDecisionAt==null?store.now():batchDecisionAt;
        var target=o.path("targetRef").isNull()?null:store.one("guard_target_binding",map("target_ref",o.path("targetRef").asText()),false);Map<String,Object> targetBudget=null;
        if(target!=null){long tid=number(target,"budget_target_id");targetBudget=budget.lock(aid,tid);budget.recover(aid,tid,now);targetBudget=budget.lock(aid,tid);now=budget.monotonic(aid);}
        List<GuardDecisionEngine.Evidence> evidence=new ArrayList<>();boolean modelAvailable=true;for(var e:selectedEvidence){
            modelAvailable&="succeeded".equals(str(e,"inference_status"));evidence.add(new GuardDecisionEngine.Evidence((JsonNode)e.get("observation_node"),e.get("score")==null?null:((Number)e.get("score")).doubleValue(),str(e,"family"),str(e,"source"),str(e,"rule_id"),flag(e.get("rule_matched")),str(e,"observation_content_sha256")));}
        var executor=target==null?null:store.get("guard_executor",number(target,"executor_id"));Instant decidedAt=now;boolean healthy=memo(cache,List.of("health",number(observation,"capture_scope_id"),number(observation,"sensor_id"),str(observation,"boot_id")),
                ()->health.current(number(observation,"capture_scope_id"),decidedAt)&&!mapper.batchGap(number(observation,"sensor_id"),str(observation,"boot_id")));
        String budgetReason=target==null?null:eligibility.protection(bundle,policy,target,o,family);
        if(budgetReason==null&&target!=null)budgetReason=budget.check(aid,number(target,"budget_target_id"),policy,now,now.plusSeconds(policy.path("maxTtlSeconds").asLong()));
        boolean capable=eligibility.capability(bundle,policy,o,family)&&modelAvailable;
        boolean validTarget=eligibility.target(target,o,now,policy,family);
        boolean authorized=eligibility.authorized(asset,bundle,binding,policy,o,executor,now,family);
        // 汇总的每条快照都须满足同一目标和运行资格，不能由最后一条观察替其余证据放行。
        // research 无目标、无执行授权，正式门禁始终拒绝；旁路不能借现场资格提升为可执行。
        if(hypotheticalPolicy==null)for(var e:evidence){JsonNode selected=e.observation();
            capable&=eligibility.capability(bundle,policy,selected,family);
            validTarget&=eligibility.target(target,selected,now,policy,family);
            healthy&=health.current(number(store.external("guard_capture_scope",selected.path("captureScopeId").asText(),false),"id"),now)
                    &&!mapper.batchGap(number(store.external("sensor_agent",selected.path("sensorId").asText(),false),"id"),selected.path("bootId").asText());
            authorized&=eligibility.authorized(asset,bundle,binding,policy,selected,executor,now,family);
        }
        if(hypotheticalPolicy!=null){capable=false;healthy=false;validTarget=false;authorized=false;}
        var gates=new GuardDecisionEngine.Gates(capable,healthy,validTarget,authorized,budgetReason);
        var outcome=GuardDecisionEngine.evaluate(policy,evidence,now,gates,family,detectionSource,ruleId);
        if(outcome.qualifiedEvidence()&&target!=null){Instant latest=outcome.selected().stream().map(e->time(e.observation(),"asOf")).max(Comparator.naturalOrder()).orElseThrow();budget.evidence(number(target,"budget_target_id"),latest);targetBudget=budget.lock(aid,number(target,"budget_target_id"));}
        // 只挂接不可变标量节点，避免 valueToTree 在大型 episode 中反复复制已校验的 JSON。
        String decisionId=id();var refs=JSON.createArrayNode();for(var e:outcome.selected()){
            var ref=JSON.createObjectNode();ref.set("observationId",e.observation().get("observationId"));ref.put("contentSha256",e.contentHash());
            ref.set("parentConnectionId",e.observation().get("parentConnectionId"));ref.set("asOf",e.observation().get("asOf"));
            ref.put("family",e.family());ref.put("source",e.source());ref.put("ruleId",e.ruleId());refs.add(ref);
        }
        var auth=binding==null?null:store.get("asset_authorization",number(binding,"authorization_id"));Map<String,Object> model=memo(cache,List.of("model",number(bundle,"model_id")),()->store.get("guard_model",number(bundle,"model_id")));
        Map<String,Object> capability=memo(cache,List.of("capability",family,o.path("addressFamily").asText(),o.path("transport").asText(),o.path("direction").asText(),o.path("profile").asText(),o.path("environment").asText()),
                ()->eligibility.matchingCapability(bundle,policy,o,family));
        JsonNode proof=object("digestVersion","guard-evidence/1","decisionContractVersion",DECISION,"protocolVersions",versions(),"decisionId",decisionId,"decisionAt",now.toString(),"family",family,"source",detectionSource,"ruleId",ruleId,"scope",scope,"environment",o.get("environment"),"modelId",model.get("public_id"),"manifestSha256",model.get("manifest_sha256"),"policySha256",p.get("definition_sha256"),"bundleId",bundle.get("public_id"),"bundleSubjectSha256",bundle.get("subject_sha256"),"capabilityId",capability==null?null:capability.get("public_id"),"capabilitySha256",capability==null?null:hash(json(capability,"payload_json")),"authorizationId",auth==null?null:auth.get("public_id"),"authorizationRevision",auth==null?null:auth.get("revision"),"targetBinding",target==null?null:json(target,"payload_json"),"budgetTargetId",target==null?null:store.get("guard_budget_target",number(target,"budget_target_id")).get("public_id"),"budgetRevision",targetBudget==null?null:targetBudget.get("revision"),"healthProofSha256",targetBudget==null?null:targetBudget.get("health_proof_sha256"),"labSession",null,"reasonCode",outcome.reason(),"detailCode",outcome.detail());
        ((com.fasterxml.jackson.databind.node.ObjectNode)proof).set("selectedObservations",refs);
        ((com.fasterxml.jackson.databind.node.ObjectNode)proof).put("triggerObservationId",str(observation,"public_id"));
        if(hypotheticalPolicy!=null){JsonNode manifest=memo(cache,List.of("model-manifest",number(model,"id")),()->json(model,"manifest_json"));
            ((com.fasterxml.jackson.databind.node.ObjectNode)proof).set("hypothetical",GuardReplayReadiness.proof(GuardReplayReadiness.evaluate(hypotheticalPolicy,manifest,evidence,now,family,detectionSource,ruleId,modelAvailable)));}
        String proofText=canonicalFact(proof);
        var decision=map("public_id",decisionId,"episode_id",episode.get("id"),"asset_id",aid,"bundle_id",bundle.get("id"),"decision_revision",episode.get("revision"),"decision_contract_version",DECISION,"decision",outcome.decision(),"reason_code",outcome.reason(),"budget_target_id",target==null?null:target.get("budget_target_id"),"budget_revision",targetBudget==null?null:targetBudget.get("revision"),"evidence_sha256",sha(proofText.getBytes(java.nio.charset.StandardCharsets.UTF_8)),"evidence_json",proofText,"decided_at",db(now));
        if(deferred!=null){deferred.add(decision);return object("id",decisionId,"episodeId",episode.get("public_id"),"decision",outcome.decision(),"reasonCode",outcome.reason(),"detailCode",outcome.detail());}
        store.insert("guard_decision",decision);
        cases.detected(episode,decision);
        store.update("guard_episode",number(episode,"id"),map("revision",number(episode,"revision")+1));store.outbox("guard.decision.recorded",decisionId,object("decisionId",decisionId));
        if(!"research".equals(o.path("environment").asText())&&outcome.reason()==null&&"block_candidate".equals(outcome.decision()))actions.create(decision,bundle,binding,target,policy,"auto",null);
        return object("id",decisionId,"episodeId",episode.get("public_id"),"decision",outcome.decision(),"reasonCode",outcome.reason(),"detailCode",outcome.detail());
    }
    /** 因果排序跨桶复核；新快照尚未消费时也使旧动作失效。 */
    private boolean latest(Map<String,Object> row){var newest=mapper.latestParent(number(row,"asset_id"),number(row,"sensor_id"),str(row,"boot_id"),str(row,"parent_connection_id"));return newest!=null&&number(newest,"id")==number(row,"id");}
    static boolean flag(Object value){return Boolean.TRUE.equals(value)||(value instanceof Number n&&n.intValue()!=0);}
}
