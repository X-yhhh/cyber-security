package com.xyh.cybersecurity.query;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/**
 * 控制台只读查询：补齐前端所需、但原模块未暴露的列表视图。
 * 控制器只做协议适配；功能权限由 PreAuthorize 声明，资源范围在服务层 SQL 内再次复核。
 * 所有端点均无副作用，不写审计以外的任何业务状态。
 */
@RestController
@RequestMapping("/api/v1")
public class ConsoleQueryController {

    private final ConsoleQueryService service;

    public ConsoleQueryController(ConsoleQueryService service) { this.service = service; }

    /** 范围内传感器及其最近一个健康窗口；只返回 sensor.read 覆盖的资产。 */
    @GetMapping("/sensors")
    @PreAuthorize("hasAuthority('sensor.read')")
    public ApiEnvelope<List<ConsoleQueryService.SensorView>> sensors(@AuthenticationPrincipal IdentityPrincipal actor,
                                                                     HttpServletRequest request) {
        return ApiEnvelope.success(service.sensors(actor.id()), requestId(request));
    }

    /** 资产授权记录；证明原文不出库，只返回引用与有效期。 */
    @GetMapping("/assets/{id}/authorizations")
    @PreAuthorize("hasAuthority('asset.authorization.read')")
    public ApiEnvelope<List<ConsoleQueryService.AuthorizationView>> authorizations(
            @PathVariable long id, @AuthenticationPrincipal IdentityPrincipal actor, HttpServletRequest request) {
        return ApiEnvelope.success(service.authorizations(actor.id(), id), requestId(request));
    }

    /** 各可见数据源的接入批次汇总（接收/拒绝计数取自 ingest_batch 事实）。 */
    @GetMapping("/data-sources/ingest-summary")
    @PreAuthorize("hasAuthority('ingest.batch.read')")
    public ApiEnvelope<List<ConsoleQueryService.IngestSummary>> ingestSummary(
            @AuthenticationPrincipal IdentityPrincipal actor, HttpServletRequest request) {
        return ApiEnvelope.success(service.ingestSummary(actor.id()), requestId(request));
    }

    /** 响应策略只读列表；首期无角色可编辑策略。 */
    @GetMapping("/response-policies")
    @PreAuthorize("hasAuthority('response.policy.read')")
    public ApiEnvelope<List<ConsoleQueryService.PolicyView>> policies(HttpServletRequest request) {
        return ApiEnvelope.success(service.policies(), requestId(request));
    }

    /** 审批台账（含已决定记录），与待审批列表使用同一资产范围规则。 */
    @GetMapping("/approvals/ledger")
    @PreAuthorize("hasAuthority('approval.read')")
    public ApiEnvelope<List<ConsoleQueryService.LedgerView>> ledger(@AuthenticationPrincipal IdentityPrincipal actor,
                                                                    HttpServletRequest request) {
        return ApiEnvelope.success(service.ledger(actor.id(), "approval.decide", false), requestId(request));
    }

    /** 当前用户本人提交的响应申请。 */
    @GetMapping("/actions/mine")
    @PreAuthorize("hasAuthority('action.request')")
    public ApiEnvelope<List<ConsoleQueryService.LedgerView>> mine(@AuthenticationPrincipal IdentityPrincipal actor,
                                                                  HttpServletRequest request) {
        return ApiEnvelope.success(service.ledger(actor.id(), "action.request", true), requestId(request));
    }

    /** 模型的发布申请记录。 */
    @GetMapping("/models/{id}/release-requests")
    @PreAuthorize("hasAuthority('model.validation.read')")
    public ApiEnvelope<List<ConsoleQueryService.ReleaseView>> releases(
            @PathVariable long id, @AuthenticationPrincipal IdentityPrincipal actor, HttpServletRequest request) {
        return ApiEnvelope.success(service.releases(actor.id(), id), requestId(request));
    }

    /** 模型部署路由（本机/远端），不含端点凭据。 */
    @GetMapping("/model-deployments")
    @PreAuthorize("hasAuthority('model.validation.read')")
    public ApiEnvelope<List<ConsoleQueryService.DeploymentView>> deployments(
            @AuthenticationPrincipal IdentityPrincipal actor, HttpServletRequest request) {
        return ApiEnvelope.success(service.deployments(actor.id()), requestId(request));
    }

    /** 漂移统计窗口；只用于观察，不触发阈值或权重变更。 */
    @GetMapping("/model-drift-windows")
    @PreAuthorize("hasAuthority('model.validation.read')")
    public ApiEnvelope<List<ConsoleQueryService.DriftView>> drift(@AuthenticationPrincipal IdentityPrincipal actor,
                                                                  HttpServletRequest request) {
        return ApiEnvelope.success(service.drift(actor.id()), requestId(request));
    }

    /** 人工反馈样本（候选训练输入，不会驱动在线自训练）。 */
    @GetMapping("/feedback-samples")
    @PreAuthorize("hasAuthority('model.validation.read')")
    public ApiEnvelope<List<ConsoleQueryService.FeedbackView>> feedback(@AuthenticationPrincipal IdentityPrincipal actor,
                                                                        HttpServletRequest request) {
        return ApiEnvelope.success(service.feedback(actor.id()), requestId(request));
    }

    /** Windows 离线训练任务台账。 */
    @GetMapping("/training-jobs")
    @PreAuthorize("hasAuthority('model.validation.read')")
    public ApiEnvelope<List<ConsoleQueryService.TrainingJobView>> trainingJobs(
            @AuthenticationPrincipal IdentityPrincipal actor, HttpServletRequest request) {
        return ApiEnvelope.success(service.trainingJobs(actor.id()), requestId(request));
    }

    /** 隔离靶场回放场景与最近运行；回放控制端点尚未实现。 */
    @GetMapping("/replay-scenarios")
    @PreAuthorize("hasAuthority('source.read')")
    public ApiEnvelope<List<ConsoleQueryService.ReplayScenarioView>> replay(HttpServletRequest request) {
        return ApiEnvelope.success(service.replayScenarios(), requestId(request));
    }

    /** 态势汇总，只包含当前身份可见范围内的计数。 */
    @GetMapping("/overview")
    public ApiEnvelope<ConsoleQueryService.OverviewView> overview(@AuthenticationPrincipal IdentityPrincipal actor,
                                                                  HttpServletRequest request) {
        return ApiEnvelope.success(service.overview(actor.id(), actor.permissions().contains("alert.read")),
                requestId(request));
    }

    /** 用户当前角色绑定（只读）。 */
    @GetMapping("/users/{id}/roles")
    @PreAuthorize("hasAuthority('iam.user.read')")
    public ApiEnvelope<List<ConsoleQueryService.RoleBindingView>> roles(@PathVariable long id,
                                                                        HttpServletRequest request) {
        return ApiEnvelope.success(service.roleBindings(id), requestId(request));
    }

    private static String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }
}
