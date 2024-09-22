package com.nazndev.abacauthservice.controller;

import com.nazndev.abacauthservice.dto.ApiResponse;
import com.nazndev.abacauthservice.entity.ApiPermission;
import com.nazndev.abacauthservice.service.ApiPermissionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api-permissions")
@RequiredArgsConstructor
public class ApiPermissionController {
    private final ApiPermissionService apiPermissionService;

    @GetMapping
    public ApiResponse<List<ApiPermission>> getAllApiPermissions() {
        List<ApiPermission> permissions = apiPermissionService.getAllApiPermissions();
        return ApiResponse.success("Retrieved API permissions", permissions);
    }

    @GetMapping("/{id}")
    public ApiResponse<ApiPermission> getApiPermissionById(@PathVariable Long id) {
        ApiPermission permission = apiPermissionService.getApiPermissionById(id).orElse(null);
        return ApiResponse.success("Retrieved API permission", permission);
    }

    @PostMapping
    public ApiResponse<ApiPermission> createApiPermission(@RequestBody ApiPermission apiPermission) {
        ApiPermission createdPermission = apiPermissionService.createApiPermission(apiPermission);
        return ApiResponse.success("API permission created successfully", createdPermission);
    }

    @PutMapping("/{id}")
    public ApiResponse<ApiPermission> updateApiPermission(@PathVariable Long id, @RequestBody ApiPermission apiPermissionDetails) {
        ApiPermission updatedPermission = apiPermissionService.updateApiPermission(id, apiPermissionDetails);
        return ApiResponse.success("API permission updated successfully", updatedPermission);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteApiPermission(@PathVariable Long id) {
        apiPermissionService.deleteApiPermission(id);
        return ResponseEntity.noContent().build();
    }
}
