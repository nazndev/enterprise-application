package com.nazndev.abacauthservice.service;

import com.nazndev.abacauthservice.entity.*;
import com.nazndev.abacauthservice.repository.*;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class StartupService {

    private static final Logger logger = LoggerFactory.getLogger(StartupService.class);

    private final RSAKeyService rsaKeyService;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PolicyRepository policyRepository;
    private final ResourceRepository resourceRepository;
    private final ActionRepository actionRepository;
    private final PolicyConditionRepository policyConditionRepository;
    private final PolicyActionResourceRepository policyActionResourceRepository;
    private final RolePolicyRepository rolePolicyRepository;
    private final AuditLogRepository auditLogRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @EventListener(ApplicationReadyEvent.class)
    public void initializeData() {
        createRSAKeyIfNotExists();
        createRolesIfNotExists();
        createActionsIfNotExists();
        createResourcesIfNotExists();
        createSuperUserIfNotExists();
        createDefaultPolicies();
    }

    private void createRSAKeyIfNotExists() {
        if (rsaKeyService.getActiveKey().isEmpty()) {
            try {
                rsaKeyService.generateAndStoreRSAKey();
                logger.info("RSA key pair generated and stored successfully.");
                logAudit("RSA_KEY", "Generated and stored new RSA key pair.");
            } catch (NoSuchAlgorithmException e) {
                logger.error("Error generating RSA keys: {}", e.getMessage(), e);
            }
        } else {
            logger.info("RSA keys already exist in the database.");
        }
    }

    private void createRolesIfNotExists() {
        if (roleRepository.findAll().isEmpty()) {
            Role adminRole = new Role();
            adminRole.setName("ROLE_ADMIN");
            roleRepository.save(adminRole);
            logAudit("ROLE", "Created ROLE_ADMIN.");

            Role userRole = new Role();
            userRole.setName("ROLE_USER");
            roleRepository.save(userRole);
            logAudit("ROLE", "Created ROLE_USER.");

            logger.info("Default roles created.");
        }
    }

    private void createActionsIfNotExists() {
        if (actionRepository.findAll().isEmpty()) {
            Action readAction = new Action();
            readAction.setName("READ");
            actionRepository.save(readAction);
            logAudit("ACTION", "Created READ action.");

            Action writeAction = new Action();
            writeAction.setName("WRITE");
            actionRepository.save(writeAction);
            logAudit("ACTION", "Created WRITE action.");

            logger.info("Default actions created.");
        }
    }

    private void createResourcesIfNotExists() {
        if (resourceRepository.findAll().isEmpty()) {
            Resource apiResource = new Resource();
            apiResource.setName("default_resource");
            apiResource.setType("API");
            resourceRepository.save(apiResource);
            logAudit("RESOURCE", "Created default_resource.");

            logger.info("Default resources created.");
        }
    }

    private void createSuperUserIfNotExists() {
        if (userRepository.findByUsername("nazim").isEmpty()) {
            User superuser = new User();
            superuser.setUsername("nazim");
            superuser.setPassword(passwordEncoder.encode("nazim"));

            Set<String> roles = new HashSet<>();
            roles.add("ROLE_ADMIN");
            superuser.setRoles(roles);

            // Set attributes
            Map<String, String> attributes = Map.of(
                    "department", "RnD",
                    "level", "Senior"
            );
            superuser.setAttributes(attributes);

            userRepository.save(superuser);
            logAudit("USER", "Created superuser nazim with ROLE_ADMIN and attributes.");

            logger.info("Superuser created.");
        }
    }


    private void createDefaultPolicies() {
        if (policyRepository.findAll().isEmpty()) {
            // Create resources
            Resource resource = resourceRepository.findByName("default_resource")
                    .orElseThrow(() -> new IllegalStateException("Resource not found"));

            // Create actions
            Action readAction = actionRepository.findByName("READ")
                    .orElseThrow(() -> new IllegalStateException("Action not found"));
            Action writeAction = actionRepository.findByName("WRITE")
                    .orElseThrow(() -> new IllegalStateException("Action not found"));

            // Create policies
            Policy readPolicy = new Policy();
            readPolicy.setResourceName(resource.getName());
            readPolicy.setAction(readAction.getName());
            policyRepository.save(readPolicy);
            logAudit("POLICY", "Created READ policy for default_resource.");

            Policy writePolicy = new Policy();
            writePolicy.setResourceName(resource.getName());
            writePolicy.setAction(writeAction.getName());
            policyRepository.save(writePolicy);
            logAudit("POLICY", "Created WRITE policy for default_resource.");

            // Link policy, action, and resource in PolicyActionResource
            createPolicyActionResource(readPolicy, readAction, resource);
            createPolicyActionResource(writePolicy, writeAction, resource);

            // Create policy conditions and update the policyCondition field
            createAndLinkPolicyCondition(readPolicy);
            createAndLinkPolicyCondition(writePolicy);

            // Link roles to policies
            Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                    .orElseThrow(() -> new IllegalStateException("Role not found"));
            linkRoleToPolicy(adminRole, readPolicy);
            linkRoleToPolicy(adminRole, writePolicy);

            logger.info("Default policies, conditions, and role-policy associations created.");
        }
    }

    private void createPolicyActionResource(Policy policy, Action action, Resource resource) {
        PolicyActionResource policyActionResource = new PolicyActionResource();
        policyActionResource.setPolicy(policy);
        policyActionResource.setAction(action);
        policyActionResource.setResource(resource);
        policyActionResourceRepository.save(policyActionResource);
        logAudit("POLICY_ACTION_RESOURCE", "Linked " + policy.getAction() + " policy to " + action.getName() + " action on " + resource.getName() + " resource.");
    }


    private void createAndLinkPolicyCondition(Policy policy) {
        PolicyCondition condition = new PolicyCondition();
        condition.setPolicy(policy);
        condition.setAttributeName("role");
        condition.setExpectedValue("ROLE_ADMIN");
        condition.setOperator("EQUALS");
        policyConditionRepository.save(condition);

        // Serialize condition to policyCondition field (simple format example)
        String policyConditionString = "role" + " " + "EQUALS" + " " + "ROLE_ADMIN";
        policy.setPolicyCondition(policyConditionString);
        policyRepository.save(policy);

        logAudit("POLICY_CONDITION", "Created condition for policy: " + policy.getAction() + " on resource: " + policy.getResourceName());
    }

    private void linkRoleToPolicy(Role role, Policy policy) {
        RolePolicy rolePolicy = new RolePolicy();
        rolePolicy.setRole(role);
        rolePolicy.setPolicy(policy);
        rolePolicyRepository.save(rolePolicy);
        logAudit("ROLE_POLICY", "Linked " + role.getName() + " to " + policy.getAction() + " policy.");
    }

    private void logAudit(String resource, String details) {
        logAudit("system", "CREATE", resource, details, auditLogRepository);
        logger.info("Audit log created: {}", details);
    }

    static void logAudit(String username, String action, String resource, String details, AuditLogRepository auditLogRepository) {
        AuditLog auditLog = new AuditLog();
        auditLog.setUsername(username);
        auditLog.setAction(action);
        auditLog.setResourceName(resource);
        auditLog.setEventTimestamp(Instant.now().toEpochMilli());
        auditLog.setDetails(details);
        auditLogRepository.save(auditLog);
    }
}
