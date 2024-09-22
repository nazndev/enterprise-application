package com.nazndev.abacauthservice.dto;

import lombok.Data;

@Data
public class ValidateTokenResponse {
    private boolean isValid;

    public ValidateTokenResponse(boolean isValid) {
        this.isValid = isValid;
    }
}
