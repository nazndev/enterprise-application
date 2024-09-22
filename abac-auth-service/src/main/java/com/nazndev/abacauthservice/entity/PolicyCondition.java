package com.nazndev.abacauthservice.entity;

import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.persistence.*;
import java.util.Objects;

@Data
@NoArgsConstructor
@Entity
@Table(name = "policy_conditions")
public class PolicyCondition {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id")
    private Policy policy;

    @Column(nullable = false)
    private String attributeName;

    @Column(nullable = false)
    private String expectedValue;

    @Column(nullable = false)
    private String operator; // e.g., EQUALS, GREATER_THAN, etc.

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PolicyCondition that = (PolicyCondition) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
