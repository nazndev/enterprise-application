package com.nazndev.abacauthservice.repository;

import com.nazndev.abacauthservice.entity.RSAKey;
import com.nazndev.abacauthservice.entity.RSAKey.KeyStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RSAKeyRepository extends JpaRepository<RSAKey, Long> {
    Optional<RSAKey> findByStatus(KeyStatus status);
    List<RSAKey> findAllByStatus(KeyStatus status);
}
