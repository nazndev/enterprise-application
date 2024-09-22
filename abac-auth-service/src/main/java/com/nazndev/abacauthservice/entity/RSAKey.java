package com.nazndev.abacauthservice.entity;

import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.persistence.*;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@Entity
@Table(name = "rsa_keys")
public class RSAKey {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Lob
    @Column(name = "private_key", nullable = false)
    private String privateKey; // Ensure this is encrypted before storing

    @Lob
    @Column(name = "public_key", nullable = false)
    private String publicKey;

    @Column(name = "key_id", nullable = false)
    private String keyId;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "status", nullable = false)
    @Enumerated(EnumType.STRING)
    private KeyStatus status;

    public enum KeyStatus {
        ACTIVE,
        INACTIVE,
        EXPIRED
    }
}

