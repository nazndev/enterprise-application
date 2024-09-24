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
import org.springframework.transaction.annotation.Transactional;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class StartupService {

    private static final Logger logger = LoggerFactory.getLogger(StartupService.class);

    private final RSAKeyService rsaKeyService;
    private final RoleRepository roleRepository;
    private final RolePolicyRepository rolePolicyRepository;
    private final UserRepository userRepository;
    private final PolicyRepository policyRepository;
    private final ResourceRepository resourceRepository;
    private final ActionRepository actionRepository;
    private final PolicyConditionRepository policyConditionRepository;
    private final PolicyActionResourceRepository policyActionResourceRepository;
    private final ApiPermissionRepository apiPermissionRepository;
    private final PolicyApiPermissionRepository policyApiPermissionRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final AuditLogRepository auditLogRepository;

    @EventListener(ApplicationReadyEvent.class)
    public void initializeData() {
        createRSAKeyIfNotExists();
        createRolesIfNotExists();
        createActionsIfNotExists();
        createResourcesIfNotExists();
        createApiPermissionsIfNotExists();
        createSuperUserIfNotExists();
        createGuestUserIfNotExists();
        createDefaultPolicies();
        createPolicyApiPermissionsIfNotExists();
        createRoleApiPermissionsIfNotExists();
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
            adminRole.setName("ADMIN");
            roleRepository.save(adminRole);
            logAudit("ROLE", "Created ADMIN.");

            Role userRole = new Role();
            userRole.setName("USER");
            roleRepository.save(userRole);
            logAudit("ROLE", "Created USER.");

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
            Resource authResource = new Resource();
            authResource.setName("AUTH_SERVICE");
            authResource.setType("API");
            resourceRepository.save(authResource);
            logAudit("RESOURCE", "Created AUTH_SERVICE resource.");

            logger.info("Default resources created.");
        }
    }

    private void createApiPermissionsIfNotExists() {
        if (apiPermissionRepository.findAll().isEmpty()) {
            // Create a single permission for all /auth/** endpoints
            ApiPermission authPermission = new ApiPermission();
            authPermission.setApiPath("/auth/**");
            authPermission.setMicroserviceName("AuthService");
            apiPermissionRepository.save(authPermission);
            logAudit("API_PERMISSION", "Created permission for /auth/**.");

            // Add permissions for the other controllers
            ApiPermission resourcePermission = new ApiPermission();
            resourcePermission.setApiPath("/resource/**");
            resourcePermission.setMicroserviceName("AuthService");
            apiPermissionRepository.save(resourcePermission);
            logAudit("API_PERMISSION", "Created permission for /resource/**.");

            ApiPermission rolePermission = new ApiPermission();
            rolePermission.setApiPath("/roles/**");
            rolePermission.setMicroserviceName("AuthService");
            apiPermissionRepository.save(rolePermission);
            logAudit("API_PERMISSION", "Created permission for /roles/**.");

            ApiPermission userPermission = new ApiPermission();
            userPermission.setApiPath("/users/**");
            userPermission.setMicroserviceName("AuthService");
            apiPermissionRepository.save(userPermission);
            logAudit("API_PERMISSION", "Created permission for /users/**.");

            logger.info("Default API permissions created.");
        }
    }

    private void createSuperUserIfNotExists() {
        if (userRepository.findByUsername("nazim").isEmpty()) {
            User superuser = new User();
            superuser.setUsername("nazim");
            superuser.setPassword(passwordEncoder.encode("nazim"));

            Set<Role> roles = new HashSet<>();
            roles.add(roleRepository.findByName("ADMIN").orElseThrow());
            superuser.setRoles(roles);

            Map<String, String> attributes = Map.of(
                    "permissions", "READ,WRITE"
            );
            superuser.setAttributes(attributes);

            userRepository.save(superuser);
            logAudit("USER", "Created superuser nazim with ADMIN and attributes.");

            logger.info("Superuser created.");
        }
    }

    private void createGuestUserIfNotExists() {
        if (userRepository.findByUsername("guest").isEmpty()) {
            User guestUser = new User();
            guestUser.setUsername("guest");
            guestUser.setPassword(passwordEncoder.encode("guest"));

            Set<Role> roles = new HashSet<>();
            roles.add(roleRepository.findByName("USER").orElseThrow());
            guestUser.setRoles(roles);

            Map<String, String> attributes = Map.of(
                    "permissions", "READ"
            );
            guestUser.setAttributes(attributes);

            userRepository.save(guestUser);
            logAudit("USER", "Created guest user with USER.");

            logger.info("Guest user created.");
        }
    }

    private void createDefaultPolicies() {
        if (policyRepository.findAll().isEmpty()) {
            Resource resource = resourceRepository.findByName("AUTH_SERVICE")
                    .orElseThrow(() -> new IllegalStateException("Resource not found"));

            Action readAction = actionRepository.findByName("READ")
                    .orElseThrow(() -> new IllegalStateException("Action not found"));
            Action writeAction = actionRepository.findByName("WRITE")
                    .orElseThrow(() -> new IllegalStateException("Action not found"));

            // Policies for ADMIN
            Policy readPolicyAdmin = new Policy();
            readPolicyAdmin.setResourceName(resource.getName());
            readPolicyAdmin.setAction(readAction.getName());
            policyRepository.save(readPolicyAdmin);
            logAudit("POLICY", "Created READ policy for AUTH_SERVICE.");

            Policy writePolicyAdmin = new Policy();
            writePolicyAdmin.setResourceName(resource.getName());
            writePolicyAdmin.setAction(writeAction.getName());
            policyRepository.save(writePolicyAdmin);
            logAudit("POLICY", "Created WRITE policy for AUTH_SERVICE.");

            // Policies for USER
            Policy readPolicyUser = new Policy();
            readPolicyUser.setResourceName(resource.getName());
            readPolicyUser.setAction(readAction.getName());
            policyRepository.save(readPolicyUser);
            logAudit("POLICY", "Created READ policy for AUTH_SERVICE for USER.");

            createPolicyActionResource(readPolicyAdmin, readAction, resource);
            createPolicyActionResource(writePolicyAdmin, writeAction, resource);
            createPolicyActionResource(readPolicyUser, readAction, resource);

            createAndLinkPolicyCondition(readPolicyAdmin, "role", "ADMIN", "EQUALS");
            createAndLinkPolicyCondition(writePolicyAdmin, "role", "ADMIN", "EQUALS");
            createAndLinkPolicyCondition(readPolicyUser, "role", "USER", "EQUALS");

            Role adminRole = roleRepository.findByName("ADMIN")
                    .orElseThrow(() -> new IllegalStateException("Role not found"));
            linkRoleToPolicy(adminRole, readPolicyAdmin);
            linkRoleToPolicy(adminRole, writePolicyAdmin);

            Role userRole = roleRepository.findByName("USER")
                    .orElseThrow(() -> new IllegalStateException("Role not found"));
            linkRoleToPolicy(userRole, readPolicyUser);

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

    private void createAndLinkPolicyCondition(Policy policy, String attributeName, String expectedValue, String operator) {
        PolicyCondition condition = new PolicyCondition();
        condition.setPolicy(policy);
        condition.setAttributeName(attributeName);
        condition.setExpectedValue(expectedValue);
        condition.setOperator(operator);
        policyConditionRepository.save(condition);

        String policyConditionString = attributeName + " " + operator + " " + expectedValue;
        policy.setPolicyCondition(policyConditionString);
        policyRepository.save(policy);

        logAudit("POLICY_CONDITION", "Created condition for policy: " + policy.getAction() + " on resource: " + policy.getResourceName() + " with condition: " + policyConditionString);
    }

    private void linkRoleToPolicy(Role role, Policy policy) {
        RolePolicy rolePolicy = new RolePolicy();
        rolePolicy.setRole(role);
        rolePolicy.setPolicy(policy);
        rolePolicyRepository.save(rolePolicy);
        logAudit("ROLE_POLICY", "Linked " + role.getName() + " to " + policy.getAction() + " policy.");
    }

    private void createPolicyApiPermissionsIfNotExists() {
        List<ApiPermission> apiPermissions = apiPermissionRepository.findAll();

        if (policyApiPermissionRepository.findAll().isEmpty()) {
            for (ApiPermission apiPermission : apiPermissions) {
                List<Policy> readPolicies = policyRepository.findByResourceNameAndAction("AUTH_SERVICE", "READ");

                for (Policy readPolicy : readPolicies) {
                    PolicyApiPermission policyApiPermission = new PolicyApiPermission();
                    policyApiPermission.setPolicy(readPolicy);
                    policyApiPermission.setApiPermission(apiPermission);
                    policyApiPermissionRepository.save(policyApiPermission);

                    logAudit("POLICY_API_PERMISSION", "Linked READ policy to API permission: " + apiPermission.getApiPath());
                }
            }
        }
    }

    @Transactional
    protected void createRoleApiPermissionsIfNotExists() {
        List<Role> roles = roleRepository.findAll();
        List<ApiPermission> permissions = apiPermissionRepository.findAllWithRoles(); // Ensure roles are eagerly fetched

        for (Role role : roles) {
            for (ApiPermission permission : permissions) {
                if (!permission.getRoles().contains(role)) {
                    permission.getRoles().add(role);
                }
            }
        }

        apiPermissionRepository.saveAll(permissions);
        logger.info("Role-API permissions associations created.");
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
