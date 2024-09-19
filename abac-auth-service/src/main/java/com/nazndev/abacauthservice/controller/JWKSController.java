package com.nazndev.abacauthservice.controller;

import com.nazndev.abacauthservice.entity.RSAKey;
import com.nazndev.abacauthservice.service.RSAKeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@RestController
public class JWKSController {

    @Autowired
    private RSAKeyService rsaKeyService;

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> getJwks() {
        Optional<RSAKey> activeKey = rsaKeyService.getActiveKey();

        if (activeKey.isPresent()) {
            RSAKey rsaKey = activeKey.get();
            return Map.of(
                    "keys", Collections.singletonList(
                            Map.of(
                                    "kty", "RSA",
                                    "kid", rsaKey.getKeyId(),
                                    "use", "sig",
                                    "alg", "RS256",
                                    "n", Base64.getUrlEncoder().encodeToString(Base64.getDecoder().decode(rsaKey.getPublicKey())),
                                    "e", "AQAB"
                            )
                    )
            );
        } else {
            throw new IllegalStateException("No active RSA key found");
        }
    }
}
