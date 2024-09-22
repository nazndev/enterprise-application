package com.nazndev.abacauthservice.controller;

import com.nazndev.abacauthservice.service.ABACService;
import com.nazndev.abacauthservice.service.AuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/resource")
@RequiredArgsConstructor
public class ResourceController {

    private final ABACService abacService;
    private final AuditService auditService;

    @GetMapping("/{resourceName}")
    public ResponseEntity<String> accessResource(@RequestHeader("username") String username,
                                                 @RequestParam("action") String action,
                                                 @PathVariable("resourceName") String resourceName) {
        if (abacService.isAllowed(username, action, resourceName)) {
            auditService.logAction(username, action, resourceName, "Access granted");
            return ResponseEntity.ok("Access granted to resource: " + resourceName);
        } else {
            auditService.logAction(username, action, resourceName, "Access denied");
            return ResponseEntity.status(403).body("Access denied to resource: " + resourceName);
        }
    }
}
