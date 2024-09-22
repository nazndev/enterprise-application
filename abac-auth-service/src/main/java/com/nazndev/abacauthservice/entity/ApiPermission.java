package com.nazndev.abacauthservice.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name = "api_permissions")
@Data
@NoArgsConstructor
public class ApiPermission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String apiPath; // e.g., "/auth/token", "/auth/*"

    @Column(nullable = false)
    private String microserviceName;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "api_role_permissions",
            joinColumns = @JoinColumn(name = "api_permission_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ApiPermission that = (ApiPermission) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
