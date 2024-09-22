package com.nazndev.abacauthservice.repository;

import com.nazndev.abacauthservice.entity.Policy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PolicyRepository extends JpaRepository<Policy, Long> {
    List<Policy> findByResourceNameAndAction(String resourceName, String action);
}
