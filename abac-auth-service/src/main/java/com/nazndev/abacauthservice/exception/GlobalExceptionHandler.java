package com.nazndev.abacauthservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

//    @ExceptionHandler(Exception.class)
//    public ResponseEntity<?> handleGlobalException(Exception ex, WebRequest request) {
//        return new ResponseEntity<>(ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
//    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Map<String, String>> handleInvalidCredentialsException(InvalidCredentialsException ex) {
        return new ResponseEntity<>(Map.of("error", ex.getMessage()), HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleGlobalException(Exception ex) {
        return new ResponseEntity<>(Map.of("error", "An unexpected error occurred"), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
