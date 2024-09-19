package com.nazndev.abacauthservice.repository;

import com.nazndev.abacauthservice.entity.Action;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ActionRepository extends JpaRepository<Action, Long> {
    Optional<Action> findByName(String actionName);
}
