package com.xyh.cybersecurity.guard;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import java.util.*;
import java.time.Instant;
import com.fasterxml.jackson.databind.JsonNode;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 隔离演练的同步 T2。只处理已批准 synthetic 会话；真实部署四道门强制关闭。
 * 默认关闭，开启仍须完整会话准入。假想候选来自 J1 同一纯判定器，不签发命令。
 */
@Service
public class GuardLabRehearsal {
    private final GuardStore store;private final GuardLabMapper mapper;private final GuardLabAdmission admission;
    private final GuardDetection detection;private final boolean enabled;
    public GuardLabRehearsal(GuardStore store,GuardLabMapper mapper,GuardLabAdmission admission,GuardDetection detection,
                            @Value("${cyber.guard.lab-rehearsal-enabled:false}") boolean enabled) {
        this.store=store;this.mapper=mapper;this.admission=admission;this.detection=detection;this.enabled=enabled;
    }
    @Transactional(isolation=Isolation.READ_COMMITTED)
    public void consume(String batchId) {
        if(!enabled)return;
        var batch=store.external("guard_observation_batch",batchId,false);
        var owner=mapper.owner(number(batch,"sensor_id"),str(batch,"boot_id"));
        if(owner==null)return;
        var row=store.get("guard_validation_session",owner);
        var run=mapper.run(owner);var p=json(run,"manifest_jcs");
        if(!"synthetic".equals(p.path("evidenceKind").asText()))return;
        requireRunning(row,run,p,store.now());
        admission.machineCurrent(run);store.lockAsset(number(batch,"asset_id"));
        var bundle=store.get("guard_release_bundle",number(row,"bundle_id"));
        var model=store.get("guard_model",number(bundle,"model_id"));
        var observations=new ArrayList<>(store.rows("guard_observation",map("batch_id",batch.get("id")),false,GuardContracts.MAX_BATCH_SIZE));
        observations.sort(Comparator.comparing(r->instant(r.get("as_of"))));
        var scored=detection.scoreBatch(observations,model);
        if(!scored.isEmpty())detection.rehearse(scored,bundle,json(store.get("guard_decision_policy",number(bundle,"policy_id")),"definition_json"));
    }

    /** 与正式执行门保持同一停止/超时边界；恢复须经会话 API，批次不能自行续期。 */
    static void requireRunning(Map<String,Object> row,Map<String,Object> run,JsonNode p,Instant now) {
        require("active".equals(str(row,"status"))&&"running".equals(str(run,"status"))
                &&run.get("stop_requested_at")==null,"LAB_RUN_NOT_RUNNING");
        require(!now.isBefore(time(p,"validFrom"))&&now.isBefore(time(p,"validUntil")),"AUTHORIZATION_INACTIVE");
        require(run.get("last_activity_at")!=null
                &&now.isBefore(instant(run.get("last_activity_at")).plusSeconds(p.path("timeoutSeconds").asLong())),"LAB_RUN_TIMED_OUT");
    }
}
