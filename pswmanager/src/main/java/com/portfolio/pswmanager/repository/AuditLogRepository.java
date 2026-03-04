package com.portfolio.pswmanager.repository;

import com.portfolio.pswmanager.model.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    Page<AuditLog> findByUserIdOrderByTimestampDesc(Long userId, Pageable pageable);

    List<AuditLog> findTop10ByUserIdOrderByTimestampDesc(Long userId);

    @Query("SELECT a FROM AuditLog a WHERE a.user.username = :username " +
            "AND a.action = 'LOGIN_FAILURE' " +
            "AND a.timestamp >= :since")
    List<AuditLog> findFailedLoginAttempts(@Param("username") String username, @Param("since") LocalDateTime since);

    void deleteByTimestampBefore(LocalDateTime cutoffDate);

    List<AuditLog> findByUserIdAndTimestampAfter(Long userId, LocalDateTime timestamp);

    Page<AuditLog> findByUserIdAndActionOrderByTimestampDesc(Long userId, AuditLog.AuditAction action, Pageable pageable);

    Page<AuditLog> findByUserIdAndStatusOrderByTimestampDesc(Long userId, AuditLog.AuditStatus status, Pageable pageable
    );
}