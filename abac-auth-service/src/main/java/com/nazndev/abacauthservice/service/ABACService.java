package com.nazndev.abacauthservice.service;

import com.nazndev.abacauthservice.entity.Policy;
import com.nazndev.abacauthservice.entity.User;
import com.nazndev.abacauthservice.repository.PolicyRepository;
import com.nazndev.abacauthservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ABACService {

    private final PolicyRepository policyRepository;
    private final UserRepository userRepository;

    public boolean isAllowed(String username, String action, String resource) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        List<Policy> policies = policyRepository.findByResourceNameAndAction(resource, action);

        for (Policy policy : policies) {
            if (evaluatePolicy(policy, user.getAttributes())) {
                return true;
            }
        }
        return false;
    }

    private boolean evaluatePolicy(Policy policy, Map<String, String> userAttributes) {
        // Here you can parse policy.getPolicyCondition() and compare it with userAttributes.
        // For simplicity, let's assume conditions are simple key-value pairs
        String[] conditions = policy.getPolicyCondition().split(",");
        for (String condition : conditions) {
            String[] keyValue = condition.split(":");
            String key = keyValue[0];
            String value = keyValue[1];

            if (!userAttributes.getOrDefault(key, "").equals(value)) {
                return false;
            }
        }
        return true;
    }
}
