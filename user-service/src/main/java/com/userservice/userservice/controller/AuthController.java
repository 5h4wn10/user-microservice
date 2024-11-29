package com.userservice.userservice.controller;

import com.userservice.userservice.dto.AuthDTO;
import com.userservice.userservice.model.Role;
import com.userservice.userservice.model.User;
import com.userservice.userservice.service.AuthService;
import com.userservice.userservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody AuthDTO authRequest) {
        boolean isRegistered = authService.registerUser(authRequest);
        if (isRegistered) {
            return ResponseEntity.status(HttpStatus.CREATED).body("User successfully registered as " + authRequest.getRole());
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username is already taken." + authRequest.getUsername());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> loginUser(@RequestBody AuthDTO authRequest) {
        boolean isAuthenticated = authService.authenticate(authRequest.getUsername(), authRequest.getPassword());
        if (isAuthenticated) {
            User user = userService.getUserByUsername(authRequest.getUsername())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

            Role role = user.getRole();
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Login successful");
            response.put("role", role);
            return ResponseEntity.ok(response);
        } else {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password");
        }
    }
}
