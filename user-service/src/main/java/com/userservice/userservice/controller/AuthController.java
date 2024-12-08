package com.userservice.userservice.controller;

import com.userservice.userservice.config.JwtTokenUtil;
import com.userservice.userservice.dto.AuthDTO;
import com.userservice.userservice.dto.UserDTO;
import com.userservice.userservice.model.Role;
import com.userservice.userservice.model.User;
import com.userservice.userservice.service.AuthService;
import com.userservice.userservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Date;
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

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

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
    public ResponseEntity<Map<String, Object>> loginUser(@RequestBody AuthDTO authRequest) {
        System.out.println("Login request received for username: " + authRequest.getUsername());

        boolean isAuthenticated = authService.authenticate(authRequest.getUsername(), authRequest.getPassword());

        if (isAuthenticated) {
            UserDTO user = userService.getUserByUsername(authRequest.getUsername());
            System.out.println("User found: " + user.getUsername() + ", Role: " + user.getRole());

            // Använd JwtTokenUtil för att generera token
            String token = jwtTokenUtil.generateToken(user.getUsername(), user.getRole());

            Map<String, Object> response = new HashMap<>();
            response.put("message", "Login successful");
            response.put("token", token);
            response.put("role", user.getRole());
            return ResponseEntity.ok(response);
        } else {
            System.out.println("Login failed for username: " + authRequest.getUsername());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password");
        }
    }
}
