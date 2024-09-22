package com.nazndev.abacauthservice.repository;

import com.nazndev.abacauthservice.entity.PolicyApiPermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PolicyApiPermissionRepository extends JpaRepository<PolicyApiPermission, Long> {
}
