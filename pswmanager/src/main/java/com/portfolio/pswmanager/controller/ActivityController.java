package com.portfolio.pswmanager.controller;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.model.dto.AuditLogDTO;
import com.portfolio.pswmanager.service.AuditService;
import com.portfolio.pswmanager.service.SessionService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
public class ActivityController {

    private static final Logger log = LoggerFactory.getLogger(ActivityController.class);

    private final AuditService auditService;
    private final SessionService sessionService;

    @GetMapping("/activity")
    public String viewActivity(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String status,
            Authentication authentication,
            Model model
    ) {
        User user = sessionService.getCurrentUser(authentication);
        log.debug("Activity history accessed by user: {}", user.getUsername());

        Pageable pageable = PageRequest.of(page, size);
        Page<AuditLog> auditPage = auditService.getUserAuditLogs(user.getId(), pageable);

        List<AuditLogDTO> activities = auditPage.getContent().stream()
                .map(AuditLogDTO::fromEntity)
                .collect(Collectors.toList());

        Map<String, Long> actionStats = auditService.getActionStatistics(user.getId());
        Map<String, Long> dailyStats = auditService.getDailyActivityStats(user.getId(), 7);

        long weeklyTotal = dailyStats != null
                ? dailyStats.values().stream().mapToLong(Long::longValue).sum()
                : 0L;

        AuditLogDTO latestActivity = activities.isEmpty() ? null : activities.getFirst();

        model.addAttribute("activities", activities);
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", auditPage.getTotalPages());
        model.addAttribute("totalItems", auditPage.getTotalElements());
        model.addAttribute("actionStats", actionStats);
        model.addAttribute("dailyStats", dailyStats);
        model.addAttribute("weeklyTotal", weeklyTotal);
        model.addAttribute("latestActivity", latestActivity);
        model.addAttribute("selectedAction", action);
        model.addAttribute("selectedStatus", status);

        log.debug("Activity history rendered - {} items on page {}", activities.size(), page);

        return "activity";
    }
}