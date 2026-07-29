package com.portfolio.pswmanager.model.dto;

import com.portfolio.pswmanager.model.AuditLog;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

@Getter
@Setter
@AllArgsConstructor
public class AuditLogDTO {

    private Long id;
    private String action;
    private String actionLabel;
    private String status;
    private String statusLabel;
    private String details;
    private String ipAddress;
    private String userAgent;
    private LocalDateTime timestamp;
    private String formattedTimestamp;
    private String relativeTime;
    private String icon;
    private String color;

    public static AuditLogDTO fromEntity(AuditLog auditLog) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");

        return new AuditLogDTO(
                auditLog.getId(),
                auditLog.getAction().name(),
                getActionLabel(auditLog.getAction()),
                auditLog.getStatus().name(),
                auditLog.getStatus() == AuditLog.AuditStatus.SUCCESS ? "Success" : "Failed",
                auditLog.getDetails(),
                auditLog.getIpAddress(),
                auditLog.getUserAgent(),
                auditLog.getTimestamp(),
                auditLog.getTimestamp().format(formatter),
                getRelativeTime(auditLog.getTimestamp()),
                getActionIcon(auditLog.getAction()),
                getStatusColor(auditLog.getStatus())
        );
    }

    private static String getActionLabel(AuditLog.AuditAction action) {
        return switch (action) {
            case LOGIN_SUCCESS -> "Login successful";
            case LOGIN_FAILURE -> "Login failed";
            case LOGOUT -> "Logout";
            case REGISTER -> "Registration";
            case CREDENTIAL_CREATE -> "Created credential";
            case CREDENTIAL_VIEW -> "Viewed vault";
            case CREDENTIAL_UPDATE -> "Updated credential";
            case CREDENTIAL_DELETE -> "Deleted credential";
            case PASSWORD_GENERATE -> "Generated password";
            case VAULT_EXPORT -> "Exported vault";
            case VAULT_IMPORT -> "Imported vault";
            case PASSWORD_CHANGE -> "Changed master password";
            case TWO_FA_ENABLED -> "Enabled 2FA";
            case TWO_FA_DISABLED -> "Disabled 2FA";
            case TWO_FA_VERIFIED -> "Verified 2FA";
            case SYSTEM_ERROR -> "System error";
        };
    }

    private static String getActionIcon(AuditLog.AuditAction action) {
        return switch (action) {
            case LOGIN_SUCCESS -> "🔓";
            case LOGIN_FAILURE -> "🚫";
            case LOGOUT -> "🔒";
            case REGISTER -> "✨";
            case CREDENTIAL_CREATE -> "➕";
            case CREDENTIAL_VIEW -> "👁";
            case CREDENTIAL_UPDATE -> "✏️";
            case CREDENTIAL_DELETE -> "🗑";
            case PASSWORD_GENERATE -> "🎲";
            case VAULT_EXPORT -> "📦";
            case VAULT_IMPORT -> "📥";
            case PASSWORD_CHANGE -> "🔐";
            case TWO_FA_ENABLED -> "🛡️";
            case TWO_FA_DISABLED -> "🔓";
            case TWO_FA_VERIFIED -> "✔️";
            case SYSTEM_ERROR -> "⚠️";
        };
    }

    private static String getStatusColor(AuditLog.AuditStatus status) {
        return status == AuditLog.AuditStatus.SUCCESS ? "success" : "error";
    }

    private static String getRelativeTime(LocalDateTime timestamp) {
        LocalDateTime now = LocalDateTime.now();

        long seconds = ChronoUnit.SECONDS.between(timestamp, now);
        if (seconds < 60) return "Just now";

        long minutes = ChronoUnit.MINUTES.between(timestamp, now);
        if (minutes < 60) return minutes + " minute" + (minutes > 1 ? "s" : "") + " ago";

        long hours = ChronoUnit.HOURS.between(timestamp, now);
        if (hours < 24) return hours + " hour" + (hours > 1 ? "s" : "") + " ago";

        long days = ChronoUnit.DAYS.between(timestamp, now);
        if (days < 7) return days + " day" + (days > 1 ? "s" : "") + " ago";

        long weeks = ChronoUnit.WEEKS.between(timestamp, now);
        if (weeks < 4) return weeks + " week" + (weeks > 1 ? "s" : "") + " ago";

        long months = ChronoUnit.MONTHS.between(timestamp, now);
        return months + " month" + (months > 1 ? "s" : "") + " ago";
    }
}