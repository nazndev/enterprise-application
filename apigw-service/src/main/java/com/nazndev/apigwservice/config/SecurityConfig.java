package com.nazndev.apigwservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                // Disable CSRF because the Gateway is stateless
                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                // Disable form-based login and the default login UI
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)

                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/actuator/**").permitAll()  // Allow unauthenticated access to these actuator endpoints
                        .anyExchange().authenticated()  // Authenticate all other requests
                );

        return http.build();
    }
}
