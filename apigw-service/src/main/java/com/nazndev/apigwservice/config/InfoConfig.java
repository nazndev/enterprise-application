package com.nazndev.apigwservice.config;

import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;

@Configuration
public class InfoConfig {

    @Bean
    public InfoContributor customInfoContributor() {
        return builder -> builder.withDetail("app", new HashMap<String, Object>() {{
            put("name", "API Gateway Service");
            put("description", "This is the API Gateway for the application.");
            put("version", "1.0.0");
        }}).build();
    }
}
