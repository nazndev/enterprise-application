package com.nazndev.abacauthservice.entity;

import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.persistence.*;

@Data
@NoArgsConstructor
@Entity
@Table(name = "policy_conditions")
public class PolicyCondition {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "policy_id")
    private Policy policy;

    @Column(nullable = false)
    private String attributeName;

    @Column(nullable = false)
    private String expectedValue;

    @Column(nullable = false)
    private String operator; // e.g., EQUALS, GREATER_THAN, etc.
}
