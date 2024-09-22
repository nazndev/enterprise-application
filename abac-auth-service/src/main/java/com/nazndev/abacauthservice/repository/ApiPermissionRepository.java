package com.nazndev.abacauthservice.repository;

import com.nazndev.abacauthservice.entity.ApiPermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ApiPermissionRepository extends JpaRepository<ApiPermission, Long> {
    Optional<ApiPermission> findByApiPath(String apiPath);

    @Query("SELECT p FROM ApiPermission p LEFT JOIN FETCH p.roles")
    List<ApiPermission> findAllWithRoles();

}

