package com.nazndev.abacauthservice.entity;

import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;
import java.util.Objects;

@Entity
@Table(name = "policies")
@Data
@NoArgsConstructor
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
    private String policyCondition; // Complex conditions can be defined here

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "policy_api_permissions",
            joinColumns = @JoinColumn(name = "policy_id"),
            inverseJoinColumns = @JoinColumn(name = "api_permission_id")
    )
    private Set<ApiPermission> apiPermissions = new HashSet<>();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Policy policy = (Policy) o;
        return Objects.equals(id, policy.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
