package com.nazndev.apigwservice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FallbackController {

    @RequestMapping("/fallback/{serviceName}")
    public ResponseEntity<String> fallback(@PathVariable("serviceName") String serviceName) {
        String fallbackMessage = String.format("The %s service is currently unavailable. Please try again later.", serviceName);
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(fallbackMessage);
    }
}
