package com.xyh.cybersecurity.inference;

import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.ingest.IngestMapper;
import com.xyh.cybersecurity.model.validation.ModelContractException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Set;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/**
 * 推理台账只读查询与回放 dry-run（路线 B §10.1 第 5 项）。
 *
 * <p>查询按数据源范围过滤（{@code inference.request.read}）；dry-run 只允许 {@code source_type='replay'} 的活动数据源，
 * 需在该数据源范围内持有 {@code model.replay.run}，走与在线相同的门禁与推理路径，但不写 {@code inference_request}、
 * 不产生告警，只写审计。</p>
 */
@Service
public class InferenceAdminService {
    static final String REPLAY_SOURCE_TYPE = "replay";
    private static final Set<String> STATUSES = Set.of(InferenceResult.SUCCEEDED, InferenceResult.REJECTED,
            InferenceResult.FAILED, InferenceResult.TIMED_OUT, InferenceResult.NOT_IN_MODEL_SCOPE);
    private static final Duration DEFAULT_WINDOW = Duration.ofHours(24);
    private static final Duration MAX_WINDOW = Duration.ofDays(7);

    private final InferenceMapper mapper;
    private final IngestMapper ingestMapper;
    private final InferenceService inference;
    private final AuditMapper auditMapper;

    public InferenceAdminService(InferenceMapper mapper, IngestMapper ingestMapper, InferenceService inference,
                                 AuditMapper auditMapper) {
        this.mapper = mapper;
        this.ingestMapper = ingestMapper;
        this.inference = inference;
        this.auditMapper = auditMapper;
    }

    public Page list(long userId, ListQuery query) {
        int page = parseInt(query.page(), 0, "page");
        int size = parseInt(query.size(), 20, "size");
        if (page < 0 || size < 1 || size > 100 || (long) page * size > Integer.MAX_VALUE) {
            throw ApiRequestException.badRequest("分页参数超出允许范围");
        }
        String status = blankToNull(query.status());
        if (status != null && !STATUSES.contains(status)) throw ApiRequestException.badRequest("推理状态无效");
        Instant to = parseInstant(query.to(), "to");
        Instant from = parseInstant(query.from(), "from");
        if (to == null) to = Instant.now();
        if (from == null) from = to.minus(DEFAULT_WINDOW);
        if (!from.isBefore(to) || Duration.between(from, to).compareTo(MAX_WINDOW) > 0) {
            throw ApiRequestException.badRequest("时间范围须满足 from < to 且不超过 7 天");
        }
        InferenceMapper.ListFilter filter = new InferenceMapper.ListFilter(parseId(query.dataSourceId(), "dataSourceId"),
                parseId(query.assetId(), "assetId"), status, parseId(query.modelVersionId(), "modelVersionId"), from, to);
        long total = mapper.countVisible(userId, filter);
        List<InferenceMapper.RequestRow> items = total == 0 ? List.of()
                : mapper.listVisible(userId, filter, page * size, size);
        return new Page(total, page, size, from, to, items);
    }

    @Transactional
    public DryRunView dryRun(long dataSourceId, long batchId, IdentityPrincipal actor, HttpServletRequest request) {
        InferenceMapper.BatchSource source = mapper.findBatchSource(batchId);
        // 批次不存在、不属于该数据源或不在调用者范围内一律 404，不泄露批次是否存在。
        if (source == null || source.dataSourceId() != dataSourceId
                || !mapper.hasSourcePermission(actor.id(), dataSourceId, "model.replay.run")) {
            throw ApiRequestException.notFound();
        }
        if (!REPLAY_SOURCE_TYPE.equals(source.sourceType()) || !"active".equals(source.sourceStatus())) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "DRY_RUN_REPLAY_SOURCE_REQUIRED",
                    "dry-run 仅允许活动的回放数据源");
        }
        List<IngestMapper.AcceptedRecord> records = ingestMapper.findAcceptedRecords(batchId);
        if (records.isEmpty()) throw ApiRequestException.conflict("该批次没有通过接入门禁的记录");
        List<InferenceResult> results;
        try {
            results = inference.dryRun(batchId, records);
        } catch (InferenceUnavailableException exception) {
            throw new ApiRequestException(HttpStatus.SERVICE_UNAVAILABLE, exception.code(), "推理暂时不可用，请稍后重试");
        } catch (ModelContractException exception) {
            throw new ApiRequestException(HttpStatus.SERVICE_UNAVAILABLE, exception.code(), "推理暂时不可用，请稍后重试");
        }
        long succeeded = results.stream().filter(r -> InferenceResult.SUCCEEDED.equals(r.status())).count();
        audit(actor.id(), batchId, dataSourceId, request, succeeded + "/" + results.size() + " records scored (dry-run)");
        return new DryRunView(batchId, dataSourceId, results);
    }

    private void audit(long actorId, long batchId, long sourceId, HttpServletRequest request, String reason) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        AuditMapper.AuditInsert audit = new AuditMapper.AuditInsert(LocalDateTime.now(), "human",
                Long.toString(actorId), "inference.dry_run", "ingest_batch", Long.toString(batchId),
                requestId instanceof String value ? value : null, "success", reason);
        auditMapper.insertAudit(audit);
        auditMapper.insertResourceScope(audit.getId(), "data_source", Long.toString(sourceId));
    }

    private static String blankToNull(String value) { return value == null || value.isBlank() ? null : value.trim(); }

    private static int parseInt(String value, int fallback, String name) {
        String text = blankToNull(value);
        if (text == null) return fallback;
        try { return Integer.parseInt(text); }
        catch (NumberFormatException exception) { throw ApiRequestException.badRequest(name + " 必须是整数"); }
    }

    private static Long parseId(String value, String name) {
        String text = blankToNull(value);
        if (text == null) return null;
        try {
            long id = Long.parseLong(text);
            if (id < 1) throw new NumberFormatException();
            return id;
        } catch (NumberFormatException exception) {
            throw ApiRequestException.badRequest(name + " 必须是正整数");
        }
    }

    private static Instant parseInstant(String value, String name) {
        String text = blankToNull(value);
        if (text == null) return null;
        try { return Instant.parse(text); }
        catch (DateTimeParseException exception) { throw ApiRequestException.badRequest(name + " 必须是 ISO-8601 UTC 时间"); }
    }

    /** 原样接收查询参数字符串，由服务层解析，保证类型错误返回 400 而不是 500。 */
    public record ListQuery(String dataSourceId, String assetId, String status, String modelVersionId,
                            String from, String to, String page, String size) { }
    public record Page(long totalElements, int page, int size, Instant from, Instant to,
                       List<InferenceMapper.RequestRow> items) { }
    public record DryRunView(long batchId, long dataSourceId, List<InferenceResult> results) { }
}
