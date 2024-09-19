package com.nazndev.abacauthservice.repository;

import com.nazndev.abacauthservice.entity.RolePolicy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RolePolicyRepository extends JpaRepository<RolePolicy, Long> {
}
