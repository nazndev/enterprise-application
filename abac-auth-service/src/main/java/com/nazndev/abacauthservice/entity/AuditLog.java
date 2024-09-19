package com.nazndev.abacauthservice.entity;

import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.persistence.*;

@Data
@NoArgsConstructor
@Entity
@Table(name = "audit_logs")
public class AuditLog {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "audit_log_seq")
    @SequenceGenerator(name = "audit_log_seq", sequenceName = "AUDIT_LOG_SEQ", allocationSize = 1)
    private Long id;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String action;

    @Column(name = "resource_name", nullable = false)
    private String resourceName;

    @Column(name = "event_timestamp", nullable = false)
    private Long eventTimestamp;

    @Lob
    @Column(name = "details", columnDefinition = "CLOB")
    private String details;
}
