package com.portfolio.pswmanager.repository;

import com.portfolio.pswmanager.model.Credential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CredentialRepository extends JpaRepository<Credential, Long> {
    List<Credential> findByUserIdAndIsActiveTrueOrderByCreatedAtDesc(Long userId);

    @Query("SELECT c FROM Credential c WHERE c.user.id = :userId AND c.isActive = true ORDER BY c.createdAt DESC")
    List<Credential> findActiveByUserId(@Param("userId") Long userId);

    List<Credential> findByUserId(Long id);
}
