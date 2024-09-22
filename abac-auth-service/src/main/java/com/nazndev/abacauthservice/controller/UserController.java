package com.nazndev.abacauthservice.controller;

import com.nazndev.abacauthservice.dto.ApiResponse;
import com.nazndev.abacauthservice.entity.User;
import com.nazndev.abacauthservice.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping
    public ApiResponse<List<User>> getAllUsers() {
        List<User> users = userService.getAllUsers();
        return ApiResponse.success("Retrieved users", users);
    }

    @GetMapping("/{id}")
    public ApiResponse<User> getUserById(@PathVariable Long id) {
        User user = userService.getUserById(id).orElse(null);
        return ApiResponse.success("Retrieved user", user);
    }

    @PostMapping
    public ApiResponse<User> createUser(@RequestBody User user) {
        User createdUser = userService.createUser(user);
        return ApiResponse.success("User created successfully", createdUser);
    }

    @PutMapping("/{id}")
    public ApiResponse<User> updateUser(@PathVariable Long id, @RequestBody User userDetails) {
        User updatedUser = userService.updateUser(id, userDetails);
        return ApiResponse.success("User updated successfully", updatedUser);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
