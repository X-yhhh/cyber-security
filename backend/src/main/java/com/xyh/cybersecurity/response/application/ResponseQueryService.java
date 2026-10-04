package com.xyh.cybersecurity.response.application;

import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.response.ResponseService;
import com.xyh.cybersecurity.response.infra.ResponseMapper;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

/** 响应只读查询边界；查询不创建审批、执行或审计业务事实。 */
@Service
public class ResponseQueryService {

    private final ResponseMapper mapper;
    private final ResponseSupport support;

    public ResponseQueryService(ResponseMapper mapper, ResponseSupport support) {
        this.mapper = mapper;
        this.support = support;
    }

    public ResponseService.Page listApprovals(long userId, int page, int size) {
        int offset = support.checkedOffset(page, size);
        return support.page(mapper.countPendingApprovals(userId), page, size,
                mapper.listPendingApprovals(userId, offset, size).stream()
                        .map(support::view).collect(Collectors.toList()));
    }

    public ResponseService.ApprovalView getApproval(long userId, long id) {
        ResponseMapper.ApprovalRow row = mapper.findApproval(id);
        if (row == null || !mapper.hasAssetPermission(userId, "approval.decide", row.assetId())) {
            throw ApiRequestException.notFound();
        }
        return support.view(row);
    }

    public ResponseService.ApprovalView getAction(long userId, long id) {
        ResponseMapper.ApprovalRow row = mapper.findApproval(id);
        if (row == null || row.requestedBy() != userId
                || !mapper.hasAssetPermission(userId, "action.request", row.assetId())) {
            throw ApiRequestException.notFound();
        }
        return support.view(row);
    }
}
