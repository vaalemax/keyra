package com.portfolio.pswmanager.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs", indexes = {
        @Index(name = "idx_audit_user", columnList = "user_id"),
        @Index(name = "idx_audit_timestamp", columnList = "timestamp"),
        @Index(name = "idx_audit_action", columnList = "action")
})
@Getter
@Setter
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable = false, length = 50)
    @Enumerated(EnumType.STRING)
    private AuditAction action;

    @Column(columnDefinition = "TEXT")
    private String details;

    @Column(length = 45)
    private String ipAddress;

    @Column(length = 500)
    private String userAgent;

    @Column(length = 50)
    private String entityType;

    private Long entityId;

    @Column(nullable = false, length = 20)
    @Enumerated(EnumType.STRING)
    private AuditStatus status;

    @Column(nullable = false, updatable = false)
    private LocalDateTime timestamp;

    @PrePersist
    protected void onCreate() {
        timestamp = LocalDateTime.now();
    }

    public enum AuditAction {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGOUT,
        REGISTER,

        CREDENTIAL_CREATE,
        CREDENTIAL_VIEW,
        CREDENTIAL_UPDATE,
        CREDENTIAL_DELETE,

        PASSWORD_GENERATE,

        VAULT_EXPORT,
        VAULT_IMPORT,

        PASSWORD_CHANGE,

        TWO_FA_ENABLED,
        TWO_FA_DISABLED,
        TWO_FA_VERIFIED,

        SYSTEM_ERROR
    }

    public enum AuditStatus {
        SUCCESS,
        FAILURE
    }
}