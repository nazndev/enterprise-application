package com.nazndev.abacauthservice.dto;

import lombok.Data;

@Data
public class ChangePasswordRequest {
    private String currentUsername; // The username of the currently authenticated user
    private String username; // The target username (for admin changes)
    private String oldPassword; // Old password for verification
    private String newPassword; // New password to set
}
