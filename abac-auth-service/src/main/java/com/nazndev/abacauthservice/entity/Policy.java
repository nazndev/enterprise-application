package com.nazndev.abacauthservice.entity;

import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.persistence.*;

@Data
@NoArgsConstructor
@Entity
@Table(name = "policies")
public class Policy {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "policy_seq")
    @SequenceGenerator(name = "policy_seq", sequenceName = "POLICY_SEQ", allocationSize = 1)
    private Long id;

    @Column(name = "resource_name", nullable = false)
    private String resourceName;

    @Column(nullable = false)
    private String action;

    @Column(name = "policy_condition")
    private String policyCondition; // JSON or DSL for complex conditions
}
