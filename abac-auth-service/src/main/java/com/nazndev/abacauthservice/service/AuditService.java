package com.nazndev.abacauthservice.service;

import com.nazndev.abacauthservice.entity.AuditLog;
import com.nazndev.abacauthservice.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public void logAction(String username, String action, String resourceName, String details) {
        StartupService.logAudit(username, action, resourceName, details, auditLogRepository);
    }
}
