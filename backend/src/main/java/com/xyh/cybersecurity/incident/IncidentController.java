package com.xyh.cybersecurity.incident;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 暴露 SQL 范围过滤后的告警与事件视图及人工研判命令。 */
@RestController
@RequestMapping("/api/v1")
public class IncidentController {

    private final IncidentService service;

    public IncidentController(IncidentService service) {
        this.service = service;
    }

    @GetMapping("/alerts")
    @PreAuthorize("hasAuthority('alert.read')")
    public ApiEnvelope<IncidentService.Page<IncidentMapper.AlertView>> alerts(
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
        return ApiEnvelope.success(service.alerts(principal.id(), page, size), requestId(request));
    }

    @GetMapping("/alerts/{id}")
    @PreAuthorize("hasAuthority('alert.read')")
    public ApiEnvelope<IncidentMapper.AlertView> alert(@PathVariable long id,
                                                        @AuthenticationPrincipal IdentityPrincipal principal,
                                                        HttpServletRequest request) {
        return ApiEnvelope.success(service.alert(principal.id(), id), requestId(request));
    }

    @GetMapping("/events")
    @PreAuthorize("hasAuthority('event.read')")
    public ApiEnvelope<IncidentService.Page<IncidentMapper.EventView>> events(
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
        return ApiEnvelope.success(service.events(principal.id(), page, size), requestId(request));
    }

    @GetMapping("/events/{id}")
    @PreAuthorize("hasAuthority('event.read')")
    public ApiEnvelope<IncidentService.EventDetail> event(@PathVariable long id,
                                                           @AuthenticationPrincipal IdentityPrincipal principal,
                                                           HttpServletRequest request) {
        return ApiEnvelope.success(service.event(principal.id(), id), requestId(request));
    }

    @PostMapping("/events/{id}/transitions")
    @PreAuthorize("hasAuthority('event.read') and hasAuthority('event.investigate')")
    public ApiEnvelope<IncidentService.EventDetail> transition(@PathVariable long id,
                                                                @Valid @RequestBody TransitionBody body,
                                                                @AuthenticationPrincipal IdentityPrincipal principal,
                                                                HttpServletRequest request) {
        return ApiEnvelope.success(service.transition(principal.id(), id, body.status(), body.reason(), request),
                requestId(request));
    }

    @PostMapping("/events/{id}/notes")
    @PreAuthorize("hasAuthority('event.read') and hasAuthority('event.investigate')")
    public ApiEnvelope<IncidentService.EventDetail> addNote(@PathVariable long id,
                                                             @Valid @RequestBody NoteBody body,
                                                             @AuthenticationPrincipal IdentityPrincipal principal,
                                                             HttpServletRequest request) {
        return ApiEnvelope.success(service.addNote(principal.id(), id, body.note(), request), requestId(request));
    }

    private String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }

    public record TransitionBody(@NotBlank @Size(max = 32) String status,
                                 @NotBlank @Size(max = 1000) String reason) { }
    public record NoteBody(@NotBlank @Size(max = 1000) String note) { }
}
