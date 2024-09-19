package com.nazndev.abacauthservice.repository;

import com.nazndev.abacauthservice.entity.PolicyCondition;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PolicyConditionRepository extends JpaRepository<PolicyCondition, Long> {
}
