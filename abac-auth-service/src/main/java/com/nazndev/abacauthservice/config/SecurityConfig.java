package com.nazndev.abacauthservice.config;

import com.nazndev.abacauthservice.entity.ApiPermission;
import com.nazndev.abacauthservice.entity.Role;
import com.nazndev.abacauthservice.repository.ApiPermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ApiPermissionRepository apiPermissionRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> {
                    // Load API permissions from the database with roles eagerly fetched
                    List<ApiPermission> permissions = apiPermissionRepository.findAllWithRoles();

                    // Allow access based on permissions
                    for (ApiPermission permission : permissions) {
                        String[] roles = permission.getRoles().stream()
                                .map(Role::getName)
                                .toArray(String[]::new);
                        auth.requestMatchers(permission.getApiPath()).hasAnyRole(roles);
                    }

                    // General rules
                    auth.requestMatchers("/auth/token", "/auth/refresh-token", "/auth/validate-token").permitAll()
                            .requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**", "/.well-known/jwks.json").permitAll()
                            .anyRequest().authenticated();
                })
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwtConfigurer -> {
                    // Additional JWT configuration if needed
                }));

        return http.build();
    }


    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
