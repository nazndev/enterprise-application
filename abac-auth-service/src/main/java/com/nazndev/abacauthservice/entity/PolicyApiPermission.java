package com.nazndev.abacauthservice.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "policy_api_permissions")
@Data
@NoArgsConstructor
public class PolicyApiPermission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "policy_id", nullable = false)
    private Policy policy;

    @ManyToOne
    @JoinColumn(name = "api_permission_id", nullable = false)
    private ApiPermission apiPermission;
}
