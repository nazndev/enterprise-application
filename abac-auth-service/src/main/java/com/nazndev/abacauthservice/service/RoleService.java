package com.nazndev.abacauthservice.service;

import com.nazndev.abacauthservice.entity.ApiPermission;
import com.nazndev.abacauthservice.entity.Role;
import com.nazndev.abacauthservice.repository.ApiPermissionRepository;
import com.nazndev.abacauthservice.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class RoleService {
    private final RoleRepository roleRepository;
    private final ApiPermissionRepository apiPermissionRepository;

    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

    public Optional<Role> getRoleById(Long id) {
        return roleRepository.findById(id);
    }

    public Role createRole(Role role, Set<Long> apiPermissionIds) {
        Role savedRole = roleRepository.save(role);
        updateApiPermissions(savedRole, apiPermissionIds);
        return savedRole;
    }

    public Role updateRole(Long id, Role roleDetails, Set<Long> apiPermissionIds) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Role not found"));
        role.setName(roleDetails.getName());
        roleRepository.save(role);
        updateApiPermissions(role, apiPermissionIds);
        return role;
    }

    public void deleteRole(Long id) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Role not found"));

        // Remove the role from any associated ApiPermissions
        for (ApiPermission permission : apiPermissionRepository.findAll()) {
            if (permission.getRoles().contains(role)) {
                permission.getRoles().remove(role);
                apiPermissionRepository.save(permission);
            }
        }

        roleRepository.deleteById(id);
    }

    private void updateApiPermissions(Role role, Set<Long> apiPermissionIds) {
        // Remove the role from current permissions
        for (ApiPermission permission : apiPermissionRepository.findAll()) {
            if (permission.getRoles().contains(role)) {
                permission.getRoles().remove(role);
                apiPermissionRepository.save(permission);
            }
        }

        // Add the role to new permissions
        for (Long apiPermissionId : apiPermissionIds) {
            ApiPermission permission = apiPermissionRepository.findById(apiPermissionId)
                    .orElseThrow(() -> new RuntimeException("API Permission not found"));
            permission.getRoles().add(role);
            apiPermissionRepository.save(permission);
        }
    }
}
