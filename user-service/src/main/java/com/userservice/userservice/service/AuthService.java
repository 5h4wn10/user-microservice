package com.userservice.userservice.service;

import com.userservice.userservice.config.JwtTokenUtil;
import com.userservice.userservice.dto.AuthDTO;
import com.userservice.userservice.dto.PatientDTO;
import com.userservice.userservice.dto.PractitionerDTO;
import com.userservice.userservice.model.Role;
import com.userservice.userservice.model.User;
import com.userservice.userservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientException;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserService userService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private WebClient.Builder webClientBuilder;
    @Autowired
    private JwtTokenUtil jwtTokenUtil; // Generera JWT-token

    @Value("${patient.service.url}")
    private String patientServiceUrl;

    @Value("${practitioner.service.url}")
    private String practitionerServiceUrl;

    public boolean registerUser(AuthDTO authRequest) {
        if (authRequest == null || authRequest.getRole() == null) {
            throw new IllegalArgumentException("Auth request or role cannot be null");
        }

        if (userRepository.existsByUsername(authRequest.getUsername())) {
            return false; // Username already taken
        }

        User user = new User();
        user.setUsername(authRequest.getUsername());
        user.setPassword(passwordEncoder.encode(authRequest.getPassword()));
        user.setFullName(authRequest.getFullName());
        user.setRole(authRequest.getRole());

        User savedUser = userRepository.save(user);



        // Generera en intern token för inter-service kommunikation
        String internalToken = jwtTokenUtil.generateToken("user-service", authRequest.getRole().name());

        if (authRequest.getRole() == Role.PATIENT) {
            createPatient(savedUser, authRequest, internalToken);
        } else if (userService.isPractitioner(user.getId())) {
            createPractitioner(savedUser, authRequest);
        }

        return true;
    }

    private void createPractitioner(User user, AuthDTO authRequest) {
        String internalToken = jwtTokenUtil.generateInternalToken(); // Använd inter-service-token här

        PractitionerDTO practitionerDTO = new PractitionerDTO();
        practitionerDTO.setUserId(user.getId());
        practitionerDTO.setName(user.getFullName());
        practitionerDTO.setSpecialty(authRequest.getSpecialty());
        practitionerDTO.setRole(user.getRole());

        try {
            webClientBuilder.build()
                    .post()
                    .uri(practitionerServiceUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + internalToken)
                    .bodyValue(practitionerDTO)
                    .retrieve()
                    .toBodilessEntity()
                    .block();
            System.out.println("Sent Token: " + internalToken);
            System.out.println("Practitioner successfully created");
        } catch (WebClientException e) {
            throw new RuntimeException("Failed to create practitioner", e);
        }
    }

    private void createPatient(User user, AuthDTO authRequest, String token) {
        PatientDTO patientDTO = new PatientDTO();
        patientDTO.setUserId(user.getId());
        patientDTO.setName(user.getFullName());
        patientDTO.setAddress(authRequest.getAddress());
        patientDTO.setPersonalNumber(authRequest.getPersonalNumber());
        patientDTO.setDateOfBirth(authRequest.getDateOfBirth());

        try {
            webClientBuilder.build()
                    .post()
                    .uri(patientServiceUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token) // Skicka token här
                    .bodyValue(patientDTO)
                    .retrieve()
                    .toBodilessEntity()
                    .block();
        } catch (WebClientException e) {
            throw new RuntimeException("Failed to create patient", e);
        }
    }

    public boolean authenticate(String username, String password) {
        return userRepository.findByUsername(username)
                .map(user -> passwordEncoder.matches(password, user.getPassword()))
                .orElse(false);
    }
}