package com.nazndev.abacauthservice.service;

import com.nazndev.abacauthservice.entity.ApiPermission;
import com.nazndev.abacauthservice.repository.ApiPermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ApiPermissionService {
    private final ApiPermissionRepository apiPermissionRepository;

    public List<ApiPermission> getAllApiPermissions() {
        return apiPermissionRepository.findAll();
    }

    public Optional<ApiPermission> getApiPermissionById(Long id) {
        return apiPermissionRepository.findById(id);
    }

    public ApiPermission createApiPermission(ApiPermission apiPermission) {
        return apiPermissionRepository.save(apiPermission);
    }

    public ApiPermission updateApiPermission(Long id, ApiPermission apiPermissionDetails) {
        ApiPermission apiPermission = apiPermissionRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("API Permission not found"));
        apiPermission.setApiPath(apiPermissionDetails.getApiPath());
        apiPermission.setMicroserviceName(apiPermissionDetails.getMicroserviceName());
        apiPermission.setRoles(apiPermissionDetails.getRoles()); // Update the roles
        return apiPermissionRepository.save(apiPermission);
    }

    public void deleteApiPermission(Long id) {
        apiPermissionRepository.deleteById(id);
    }
}
