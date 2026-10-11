package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** v5 案件保持单资产范围；人工结案/反馈不改变策略证据，也不触发在线训练。 */
@Service
public class GuardCases {
    private final GuardStore store;private final GuardAccess access;
    public GuardCases(GuardStore store,GuardAccess access){this.store=store;this.access=access;}
    public void detected(Map<String,Object> episode,Map<String,Object> decision){
        if("observe".equals(str(decision,"decision")))return;var link=store.one("guard_event_episode",map("episode_id",episode.get("id")),false);Map<String,Object> event;
        if(link==null){event=store.add("security_event",map("guard_asset_id",episode.get("asset_id"),"event_key","guard:"+episode.get("public_id"),"title","主机对象流量证据","category",episode.get("family"),"severity","medium","status","open","risk_rule_version",DECISION,"first_seen_at",decision.get("decided_at"),"last_seen_at",decision.get("decided_at")));
            store.add("guard_event_episode",map("event_id",event.get("id"),"episode_id",episode.get("id")));
        }else{event=store.get("security_event",number(link,"event_id"));store.update("security_event",number(event,"id"),map("last_seen_at",decision.get("decided_at")));}
        timeline(number(event,"id"),"guard.decision",null,"追加对象证据",object("decisionId",decision.get("public_id"),"episodeId",episode.get("public_id"),"decision",decision.get("decision"),"reasonCode",decision.get("reason_code")));
    }
    /**
     * 研究批次已经完成全部判定且不能创建动作；批量写案件链接与时间线，保留每个 episode 的独立事实。
     * 同批每个 episode 只出现一次，旧案件最后时间与原逐条 detected 使用同一 decided_at。
     */
    public void detectedBatch(Map<Long,Map<String,Object>> episodes,List<Map<String,Object>> decisions){
        var alerts=decisions.stream().filter(d->!"observe".equals(str(d,"decision"))).toList();
        if(alerts.isEmpty())return;
        var links=new HashMap<Long,Map<String,Object>>();
        for(var row:store.byKeys("guard_event_episode",alerts.stream().map(d->map("episode_id",d.get("episode_id"))).toList(),false))
            links.merge(number(row,"episode_id"),row,(a,b)->number(a,"id")>number(b,"id")?a:b);
        var newEvents=new ArrayList<Map<String,Object>>();var eventsByEpisode=new HashMap<Long,Map<String,Object>>();
        var updates=new LinkedHashMap<Long,Map<String,Object>>();
        for(var d:alerts){long eid=number(d,"episode_id");var episode=episodes.get(eid);var link=links.get(eid);
            if(link==null){var event=map("guard_asset_id",episode.get("asset_id"),"event_key","guard:"+episode.get("public_id"),"title","主机对象流量证据","category",episode.get("family"),"severity","medium","status","open","risk_rule_version",DECISION,"first_seen_at",d.get("decided_at"),"last_seen_at",d.get("decided_at"));newEvents.add(event);eventsByEpisode.put(eid,event);}
            else{updates.put(number(link,"event_id"),map("id",link.get("event_id"),"last_seen_at",d.get("decided_at")));eventsByEpisode.put(eid,map("id",link.get("event_id")));}}
        if(!newEvents.isEmpty())store.addAllReturning("security_event",newEvents);
        store.updateAll("security_event",new ArrayList<>(updates.values()));
        var newLinks=new ArrayList<Map<String,Object>>();var timelines=new ArrayList<Map<String,Object>>();
        var recordedAt=db(store.now());
        for(var d:alerts){long eid=number(d,"episode_id");var episode=episodes.get(eid);Object eventId=eventsByEpisode.get(eid).get("id");
            if(!links.containsKey(eid))newLinks.add(map("event_id",eventId,"episode_id",eid));
            timelines.add(map("event_id",eventId,"occurred_at",recordedAt,"entry_type","guard.decision","actor_type","system","actor_id","guard","summary","追加对象证据","details_json",canonical(object("decisionId",d.get("public_id"),"episodeId",episode.get("public_id"),"decision",d.get("decision"),"reasonCode",d.get("reason_code")))));}
        store.addAll("guard_event_episode",newLinks);store.insertAll("event_timeline",timelines);
    }
    public JsonNode transition(String id,JsonNode b,String revision){fields(b,"expectedRevision to reason","");var event=store.external("security_event",id,false);require(event.get("guard_asset_id")!=null,"RESOURCE_NOT_FOUND");long aid=number(event,"guard_asset_id");access.permission("event.manage",aid);store.lockAsset(aid);event=store.external("security_event",id,true);access.revision(event,revision);require(integer(b,"expectedRevision",1,Long.MAX_VALUE)==number(event,"revision"),"REVISION_CONFLICT");text(b,"reason");String to=text(b,"to"),from=str(event,"status");
        Map<String,Set<String>> transitions=Map.of("open",Set.of("investigating","false_positive"),"investigating",Set.of("contained","resolved","false_positive"),"contained",Set.of("investigating","resolved"),"resolved",Set.of("closed","investigating"),"false_positive",Set.of("closed","investigating"),"closed",Set.of());
        require(transitions.getOrDefault(from,Set.of()).contains(to),"STATE_CONFLICT");
        if(to.equals("contained")){boolean applied=false;for(var link:store.rows("guard_event_episode",map("event_id",event.get("id")),false,1000))for(var d:store.rows("guard_decision",map("episode_id",link.get("episode_id")),false,1000))applied|=store.one("guard_action",map("decision_id",d.get("id"),"observed_state","applied"),false)!=null;require(applied,"ACTION_EFFECT_UNVERIFIED");}
        store.update("security_event",number(event,"id"),map("status",to,"revision",number(event,"revision")+1));timeline(number(event,"id"),"guard.transition",access.human(),text(b,"reason"),object("from",from,"to",to));store.audit(access.human(),"guard.event.transition",id,aid,null,b);return object("id",id,"status",to,"revision",number(event,"revision")+1);}
    public JsonNode note(String id,JsonNode b){fields(b,"note","");var e=store.external("security_event",id,false);require(e.get("guard_asset_id")!=null,"RESOURCE_NOT_FOUND");access.permission("event.manage",number(e,"guard_asset_id"));timeline(number(e,"id"),"guard.note",access.human(),text(b,"note"),object());return object("accepted",true);}
    public JsonNode feedback(JsonNode b){fields(b,"observationId label evidenceRef","");var o=store.external("guard_observation",uuid(b,"observationId"),false);access.permission("feedback.label",number(o,"asset_id"));require(Set.of("benign","attack","ambiguous").contains(text(b,"label")),"INVALID_LABEL");
        var f=store.add("guard_feedback",map("asset_id",o.get("asset_id"),"observation_id",o.get("id"),"label",text(b,"label"),"evidence_ref",text(b,"evidenceRef"),"created_by",access.human()));store.audit(access.human(),"guard.feedback.labelled",str(f,"public_id"),number(o,"asset_id"),null,b);return object("id",f.get("public_id"),"status","pending","revision",1,"trainingEligible",false);}
    public JsonNode review(String id,JsonNode b,String revision){var f=store.external("guard_feedback",id,false);access.permission("feedback.review",number(f,"asset_id"));store.lockAsset(number(f,"asset_id"));f=store.external("guard_feedback",id,true);access.revision(f,revision);access.different(f,"created_by");GuardAdministration.decisionBody(b);require("pending".equals(str(f,"status")),"STATE_CONFLICT");String status=text(b,"decision").equals("approve")?"reviewed":"rejected";
        store.update("guard_feedback",number(f,"id"),map("reviewed_by",access.human(),"status",status,"review_reason",text(b,"reason"),"revision",number(f,"revision")+1));store.audit(access.human(),"guard.feedback.reviewed",id,number(f,"asset_id"),null,b);return object("id",id,"status",status,"trainingEligible",false,"revision",number(f,"revision")+1);}
    private void timeline(long event,String type,Long actor,String summary,JsonNode detail){store.insert("event_timeline",map("event_id",event,"occurred_at",db(store.now()),"entry_type",type,"actor_type",actor==null?"system":"human","actor_id",actor==null?"guard":actor.toString(),"summary",summary,"details_json",canonical(detail)));}
}
