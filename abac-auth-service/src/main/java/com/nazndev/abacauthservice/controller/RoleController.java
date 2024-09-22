package com.nazndev.abacauthservice.controller;

import com.nazndev.abacauthservice.dto.ApiResponse;
import com.nazndev.abacauthservice.entity.Role;
import com.nazndev.abacauthservice.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/roles")
@RequiredArgsConstructor
public class RoleController {
    private final RoleService roleService;

    @GetMapping
    public ApiResponse<List<Role>> getAllRoles() {
        List<Role> roles = roleService.getAllRoles();
        return ApiResponse.success("Retrieved roles", roles);
    }

    @GetMapping("/{id}")
    public ApiResponse<Role> getRoleById(@PathVariable Long id) {
        Role role = roleService.getRoleById(id).orElse(null);
        return ApiResponse.success("Retrieved role", role);
    }

    @PostMapping
    public ApiResponse<Role> createRole(@RequestBody Role role, @RequestParam Set<Long> apiPermissionIds) {
        Role createdRole = roleService.createRole(role, apiPermissionIds);
        return ApiResponse.success("Role created successfully", createdRole);
    }

    @PutMapping("/{id}")
    public ApiResponse<Role> updateRole(@PathVariable Long id, @RequestBody Role roleDetails, @RequestParam Set<Long> apiPermissionIds) {
        Role updatedRole = roleService.updateRole(id, roleDetails, apiPermissionIds);
        return ApiResponse.success("Role updated successfully", updatedRole);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteRole(@PathVariable Long id) {
        roleService.deleteRole(id);
        return ResponseEntity.noContent().build();
    }
}
