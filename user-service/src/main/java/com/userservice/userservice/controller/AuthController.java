package com.userservice.userservice.controller;

import com.userservice.userservice.dto.AuthDTO;
import com.userservice.userservice.dto.UserDTO;
import com.userservice.userservice.service.AuthService;
import com.userservice.userservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserService userService;


    private static final String SECRET_KEY = "NYCKEL"; // Byt ut till en stark nyckel

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
    public ResponseEntity<String> loginUser(@RequestBody AuthDTO authRequest) {
        throw new UnsupportedOperationException("Login is managed by Keycloak. Use the Keycloak login endpoint.");
    }
}
