package com.nazndev.abacauthservice.config;

import com.nazndev.abacauthservice.entity.ApiPermission;
import com.nazndev.abacauthservice.entity.Role;
import com.nazndev.abacauthservice.repository.ApiPermissionRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
    private final ApiPermissionRepository apiPermissionRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        logger.info("Starting SecurityFilterChain configuration");

        http
                .csrf(csrf -> {
                    csrf.disable();
                    logger.info("CSRF protection disabled");
                })
                .authorizeHttpRequests(auth -> {
                    logger.info("Configuring API permissions based on roles");

                    // Permit access to auth-related endpoints without authentication
                    auth.requestMatchers("/auth/token", "/auth/refresh-token", "/auth/validate-token").permitAll()
                            .requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**", "/.well-known/jwks.json").permitAll();

                    // Load API permissions from the database with roles eagerly fetched
                    List<ApiPermission> permissions = apiPermissionRepository.findAllWithRoles();

                    // Apply role-based access control based on the permissions from the database
                    for (ApiPermission permission : permissions) {
                        String[] authorities = permission.getRoles().stream()
                                .map(Role::getName)
                                .toArray(String[]::new);

                        logger.info("Mapping API path {} to roles {}", permission.getApiPath(), authorities);
                        auth.requestMatchers(permission.getApiPath()).hasAnyAuthority(authorities);
                    }

                    // Secure all other endpoints
                    auth.anyRequest().authenticated();

                    logger.info("General authorization rules applied");
                })
                .sessionManagement(session -> {
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                    logger.info("Session management set to STATELESS");
                })
                .oauth2ResourceServer(oauth2 -> {
                    oauth2.jwt(jwtConfigurer -> {
                        logger.info("OAuth2 resource server configured with JWT support");
                    });
                });

        logger.info("SecurityFilterChain configured successfully");
        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        logger.info("BCryptPasswordEncoder bean created");
        return new BCryptPasswordEncoder();
    }
}
