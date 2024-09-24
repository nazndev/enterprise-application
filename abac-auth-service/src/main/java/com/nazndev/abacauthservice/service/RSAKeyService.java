package com.nazndev.abacauthservice.service;

import com.nazndev.abacauthservice.entity.RSAKey;
import com.nazndev.abacauthservice.entity.RSAKey.KeyStatus;
import com.nazndev.abacauthservice.repository.RSAKeyRepository;
import com.nazndev.abacauthservice.util.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RSAKeyService {

    private static final Logger logger = LoggerFactory.getLogger(RSAKeyService.class);

    private final RSAKeyRepository rsaKeyRepository;

    public void generateAndStoreRSAKey() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRSAKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey();
        rsaKey.setKeyId(UUID.randomUUID().toString());
        rsaKey.setPublicKey(Base64.getUrlEncoder().encodeToString(publicKey.getEncoded()));
        rsaKey.setPrivateKey(Base64.getUrlEncoder().encodeToString(privateKey.getEncoded()));
        rsaKey.setCreatedAt(LocalDateTime.now());
        rsaKey.setExpiresAt(LocalDateTime.now().plusDays(1)); // Keys rotate daily
        rsaKey.setStatus(KeyStatus.ACTIVE);

        deactivateOldKeys();

        rsaKeyRepository.save(rsaKey);
    }

    public Optional<RSAKey> getActiveKey() {
        return rsaKeyRepository.findByStatus(KeyStatus.ACTIVE);
    }

    public List<RSAKey> getAllKeys() {
        return rsaKeyRepository.findAll();
    }

    private KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private void deactivateOldKeys() {
        rsaKeyRepository.findAllByStatus(KeyStatus.ACTIVE).forEach(key -> {
            key.setStatus(KeyStatus.INACTIVE);
            rsaKeyRepository.save(key);
        });
    }

    public PrivateKey getPrivateKey(String base64PrivateKey) throws Exception {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] decodedKey = Base64.getUrlDecoder().decode(base64PrivateKey);
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
        } catch (Exception e) {
            logger.error("Error retrieving PrivateKey: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to retrieve PrivateKey", e);
        }
    }

    public PublicKey getPublicKey(String base64PublicKey) throws Exception {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] decodedKey = Base64.getUrlDecoder().decode(base64PublicKey);
            return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
        } catch (Exception e) {
            logger.error("Error retrieving PublicKey: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to retrieve PublicKey", e);
        }
    }

}
