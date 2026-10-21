package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * BE-23 A1 的平台边界回归：内存替身驱动真实登记与目录服务，不连接数据库、远端或执行器。
 * Linux 只能观察告警；签名证据有效也不能授予 Linux 自动执行能力，
 * 已批准的其他平台能力不能替代 Linux 资产缺失的执行能力。
 */
class GuardLinuxPlatformTest {
    /** Linux 资产登记保留真实平台标签，登记本身不创建执行能力。 */
    @Test void linuxAssetCanBeRegistered() {
        var store=mock(GuardStore.class);var assetId=id();
        var administration=new GuardAdministration(store,mock(GuardMapper.class),mock(GuardAccess.class),null);
        when(store.add(eq("asset"),anyMap())).thenReturn(map("id",1L,"public_id",assetId));

        var result=administration.asset(object("assetKey","offline-linux-host","platform","linux",
                "environment","authorized","owner","offline-owner"));

        assertThat(result.path("id").asText()).isEqualTo(assetId);
        verify(store).add(eq("asset"),argThat(values->"linux".equals(json(values,"labels_json").path("platform").asText())
                &&"authorized".equals(values.get("environment"))&&"active".equals(values.get("status"))));
        verify(store,never()).add(eq("guard_capability"),anyMap());
    }

    /** 传感器与零能力执行器均可登记；机器身份不会授予任何平台能力或自动化资格。 */
    @ParameterizedTest
    @ValueSource(booleans={false,true})
    void linuxSensorAndZeroCapabilityExecutorCanBeRegistered(boolean executor) {
        var store=mock(GuardStore.class);var assetId=id();var clientId=id();
        var administration=new GuardAdministration(store,mock(GuardMapper.class),mock(GuardAccess.class),null);
        var asset=map("id",1L,"public_id",assetId,"labels_json",canonical(object("platform","linux")));
        when(store.external("asset",assetId,false)).thenReturn(asset);
        when(store.now()).thenReturn(Instant.parse("2026-10-21T00:00:00Z"));
        when(store.insert(eq("sensor_agent"),anyMap())).thenReturn(map("id",2L));
        when(store.add(eq("api_client"),anyMap())).thenReturn(map("id",3L,"public_id",clientId));
        var request=object("assetId",assetId,"platform","linux");
        request.put(executor?"capabilityProbeRef":"captureScopeId",executor?"offline-observer-probe":id());

        var result=administration.machine(request,executor);

        assertThat(result.path("id").asText()).isNotEmpty();
        assertThat(result.path("clientId").asText()).isEqualTo(clientId);
        assertThat(result.path("status").asText()).isEqualTo(executor?"pending":"active");
        if(executor)verify(store).insert(eq("guard_executor"),argThat(values->"linux".equals(values.get("platform"))
                &&"pending".equals(values.get("status"))&&"unverified".equals(values.get("adapter_version"))&&!values.containsKey("capability_hash")));
        else verify(store).insert(eq("sensor_agent"),argThat(values->"linux".equals(values.get("platform"))&&"[]".equals(values.get("capabilities_json"))));
        verify(store,never()).add(eq("guard_capability"),anyMap());
        verify(store,never()).add(eq("guard_bundle_capability"),anyMap());
    }

    @ParameterizedTest
    @ValueSource(strings={"research","alert_only","lab_auto","authorized_auto"})
    void linuxServiceExecutionCapabilityMustBeRejected(String level) {
        var store=mock(GuardStore.class);var access=mock(GuardAccess.class);
        var artifacts=mock(GuardArtifacts.class);var signatures=mock(GuardSignatures.class);
        var catalog=new GuardCatalog(store,access,null,artifacts,null,signatures,false);
        var request=capability(level,"peer_service");
        var bound=request.deepCopy();bound.remove(List.of("evidenceRef","evidenceSha256","runnerIdentity","exemptionEvidenceRef"));
        var report=object("passed",true,"capability",bound,"protocolVersions",versions());
        when(artifacts.json("offline-platform-report.json","a".repeat(64))).thenReturn(report);
        when(signatures.report(report,"offline-runner")).thenReturn(report);
        when(store.add(eq("guard_capability"),anyMap())).thenReturn(map("public_id",id()));

        assertThatThrownBy(()->catalog.capability(request))
                .isInstanceOfSatisfying(ApiRequestException.class,
                        e->assertThat(e.code()).isEqualTo("CAPABILITY_NOT_SUPPORTED"));
        verifyNoInteractions(artifacts,signatures,store);
    }

    /** 对照：现有 peer_inbound 平台门槛应在读取任何报告或写入事实前拒绝 Linux。 */
    @Test void linuxInboundExecutionCapabilityIsRejected() {
        var store=mock(GuardStore.class);var access=mock(GuardAccess.class);
        var artifacts=mock(GuardArtifacts.class);var signatures=mock(GuardSignatures.class);
        var catalog=new GuardCatalog(store,access,null,artifacts,null,signatures,false);
        assertThatThrownBy(()->catalog.capability(capability("authorized_auto","peer_inbound")))
                .isInstanceOfSatisfying(ApiRequestException.class,
                        e->assertThat(e.code()).isEqualTo("CAPABILITY_NOT_SUPPORTED"));
        verifyNoInteractions(artifacts,signatures,store);
    }

    /** 未知平台不能借 peer_service 绕过平台白名单，且不得读取证据或写入事实。 */
    @Test void unknownPlatformServiceCapabilityIsRejected() {
        var store=mock(GuardStore.class);var artifacts=mock(GuardArtifacts.class);var signatures=mock(GuardSignatures.class);
        var catalog=new GuardCatalog(store,mock(GuardAccess.class),null,artifacts,null,signatures,false);
        var request=capability("authorized_auto","peer_service").put("platform","freebsd");
        assertThatThrownBy(()->catalog.capability(request))
                .isInstanceOfSatisfying(ApiRequestException.class,
                        e->assertThat(e.code()).isEqualTo("CAPABILITY_NOT_SUPPORTED"));
        verifyNoInteractions(artifacts,signatures,store);
    }

    /** 对照：macOS/Windows 的 peer_service 能力继续按原有签名证据规则登记。 */
    @ParameterizedTest
    @ValueSource(strings={"macos","windows"})
    void supportedPlatformServiceCapabilityRegistrationIsUnchanged(String platform) {
        var store=mock(GuardStore.class);var artifacts=mock(GuardArtifacts.class);var signatures=mock(GuardSignatures.class);
        var catalog=new GuardCatalog(store,mock(GuardAccess.class),null,artifacts,null,signatures,false);
        var request=capability("authorized_auto","peer_service").put("platform",platform);
        var bound=request.deepCopy();bound.remove(List.of("evidenceRef","evidenceSha256","runnerIdentity","exemptionEvidenceRef"));
        var report=object("passed",true,"capability",bound,"protocolVersions",versions());
        when(artifacts.json("offline-platform-report.json","a".repeat(64))).thenReturn(report);
        when(signatures.report(report,"offline-runner")).thenReturn(report);
        when(store.add(eq("guard_capability"),anyMap())).thenReturn(map("public_id",id()));

        assertThat(catalog.capability(request).path("level").asText()).isEqualTo("authorized_auto");
        verify(store).add(eq("guard_capability"),argThat(values->platform.equals(values.get("platform"))));
    }

    /**
     * 使用非空且等级充分的 macOS 能力，排除“不可能创建空能力组合”的夹具误报。
     * Linux 只告警，不得借其他平台能力激活 auto，也不得先挂起现有绑定。
     */
    @ParameterizedTest
    @ValueSource(strings={"lab","authorized"})
    void linuxAutoActivationIsRejectedBeforeSuspendingBindings(String environment) {
        var fixture=new ActivationFixture("auto",environment);
        assertThatThrownBy(fixture::activate)
                .isInstanceOfSatisfying(ApiRequestException.class,
                        e->assertThat(e.code()).isEqualTo("CAPABILITY_NOT_SUPPORTED"));
        verify(fixture.store,never()).add(eq("guard_asset_binding"),anyMap());
        verify(fixture.store,never()).update(anyString(),anyLong(),anyMap());
    }

    /** Linux 仅精确的 alert_only 可激活；未知或空模式也必须拒绝。 */
    @ParameterizedTest
    @ValueSource(strings={"unknown",""})
    void linuxUnknownPolicyModeIsRejected(String mode) {
        var fixture=new ActivationFixture(mode,"authorized");
        assertThatThrownBy(fixture::activate)
                .isInstanceOfSatisfying(ApiRequestException.class,
                        e->assertThat(e.code()).isEqualTo("CAPABILITY_NOT_SUPPORTED"));
        verify(fixture.store,never()).add(eq("guard_asset_binding"),anyMap());
        verify(fixture.store,never()).update(anyString(),anyLong(),anyMap());
    }

    /** 对照：同一资产、授权及组合引用仅将已审查策略改为只告警，应允许激活。 */
    @ParameterizedTest
    @ValueSource(strings={"lab","authorized"})
    void linuxAlertOnlyActivationIsAllowed(String environment) {
        var fixture=new ActivationFixture("alert_only",environment);
        assertThat(fixture.activate().path("status").asText()).isEqualTo("active");
        verify(fixture.store).add(eq("guard_asset_binding"),anyMap());
        verify(fixture.store).update("guard_asset_binding",8L,map("status","suspended","revision",3L));
    }

    /** lab 资产可没有平台标签；这次收紧只判断 Linux，不引入通用的平台相等检查。 */
    @ParameterizedTest
    @ValueSource(strings={"macos","windows",""})
    void existingLabAutoActivationWithOtherOrMissingPlatformRemainsAllowed(String platform) {
        var fixture=new ActivationFixture("auto","lab",platform);
        assertThat(fixture.activate().path("status").asText()).isEqualTo("active");
        verify(fixture.store).add(eq("guard_asset_binding"),anyMap());
    }

    private static ObjectNode capability(String level,String scope) {
        return object("capabilityKey","offline-linux-probe","version","1","platform","linux",
                "adapterVersion","offline-adapter","addressFamily","ipv4","transport","tcp",
                "direction","inbound","family","dos_slow","profile","flow-prefix-v1",
                "behaviorScope",List.of("publisher_documented"),"latencyLimits",object("maxMillis",1000),
                "level",level,"scope",scope,"evidenceRef","offline-platform-report.json",
                "evidenceSha256","a".repeat(64),"runnerIdentity","offline-runner");
    }

    /** 只替换持久化及权限依赖，保留真实激活路径及非空能力关联。 */
    private static final class ActivationFixture {
        final GuardStore store=mock(GuardStore.class);
        final GuardCatalog catalog=new GuardCatalog(store,mock(GuardAccess.class),null,null,null,null,false);
        final String bundleId=id(),assetId=id(),authorizationId=id();
        ActivationFixture(String mode,String environment) {this(mode,environment,"linux");}
        ActivationFixture(String mode,String environment,String platform) {
            var now=Instant.parse("2026-10-21T00:00:00Z");
            var bundle=map("id",2L,"public_id",bundleId,"model_id",4L,"policy_id",5L,
                    "status","approved","environment",environment,"revision",1L);
            var asset=map("id",1L,"public_id",assetId,"status","active","environment",environment,
                    "labels_json",canonical(platform.isEmpty()?object():object("platform",platform)));
            var capabilityId=id();
            when(store.now()).thenReturn(now);
            when(store.external(eq("guard_release_bundle"),eq(bundleId),anyBoolean())).thenReturn(bundle);
            when(store.one("guard_model",map("id",4L),true))
                    .thenReturn(map("id",4L,"validation_status","validated"));
            when(store.external("asset",assetId,false)).thenReturn(asset);
            when(store.lockAsset(1L)).thenReturn(asset);
            when(store.external("asset_authorization",authorizationId,true)).thenReturn(map(
                    "id",3L,"asset_id",1L,"status","active","revision",1L,
                    "valid_from",db(now.minusSeconds(60)),"valid_until",db(now.plusSeconds(3600)),
                    "scope_json",canonical(object("observationAllowed",true,"executionScopes",List.of()))));
            when(store.get("guard_decision_policy",5L)).thenReturn(map("status","reviewed",
                    "definition_json",canonical(object("mode",mode,"supportedCapabilityIds",List.of(capabilityId)))));
            when(store.rows("guard_bundle_capability",map("bundle_id",2L),false,100))
                    .thenReturn(List.of(map("bundle_id",2L,"capability_id",6L)));
            when(store.get("guard_capability",6L)).thenReturn(map("id",6L,"public_id",capabilityId,
                    "platform","macos","scope","peer_service","level","authorized_auto"));
            when(store.add(eq("guard_asset_binding"),anyMap()))
                    .thenReturn(map("id",7L,"public_id",id()));
            when(store.rows("guard_asset_binding",map("asset_id",1L,"status","active"),true,100))
                    .thenReturn(List.of(map("id",8L,"status","active","revision",2L)));
        }
        com.fasterxml.jackson.databind.JsonNode activate() {
            return catalog.activate(bundleId,object("assetIds",List.of(assetId),
                    "authorizationIds",List.of(authorizationId)),"1");
        }
    }
}
