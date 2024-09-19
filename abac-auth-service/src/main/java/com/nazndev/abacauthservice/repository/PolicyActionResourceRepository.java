package com.nazndev.abacauthservice.repository;

import com.nazndev.abacauthservice.entity.PolicyActionResource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PolicyActionResourceRepository extends JpaRepository<PolicyActionResource, Long> {
}
