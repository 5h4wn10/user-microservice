package com.userservice.userservice.service;

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

import java.util.Map;
import java.util.Optional;

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

    @Value("${patient.service.url}")
    private String patientServiceUrl;

    @Value("${practitioner.service.url}")
    private String practitionerServiceUrl;

    @Value("${keycloak.auth-server-url}")
    private String keycloakUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

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

        // Hämta en access token från Keycloak
        String internalToken = fetchAccessToken();

        if (authRequest.getRole() == Role.PATIENT) {
            createPatient(savedUser, authRequest, internalToken);
        } else if (userService.isPractitioner(user.getId())) {
            createPractitioner(savedUser, authRequest, internalToken);
        }

        return true;
    }

    private String fetchAccessToken() {
        try {
            Map<String, Object> response = webClientBuilder.build()
                    .post()
                    .uri(keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token")
                    .header(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .bodyValue("grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + clientSecret)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            System.out.println("Token fetch response: " + response);
            return (String) response.get("access_token");
        } catch (WebClientException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to fetch access token from Keycloak", e);
        }
    }

    private void createPractitioner(User user, AuthDTO authRequest, String token) {
        PractitionerDTO practitionerDTO = new PractitionerDTO();
        practitionerDTO.setUserId(user.getId());
        practitionerDTO.setName(user.getUsername());
        practitionerDTO.setSpecialty(authRequest.getSpecialty());
        practitionerDTO.setRole(user.getRole());

        postToService(practitionerServiceUrl, practitionerDTO, token);

    }

    private void createPatient(User user, AuthDTO authRequest, String token) {
        PatientDTO patientDTO = new PatientDTO();
        patientDTO.setUserId(user.getId());
        patientDTO.setName(user.getFullName());
        patientDTO.setAddress(authRequest.getAddress());
        patientDTO.setPersonalNumber(authRequest.getPersonalNumber());
        patientDTO.setDateOfBirth(authRequest.getDateOfBirth());

        postToService(patientServiceUrl, patientDTO, token);

    }

    private void postToService(String url, Object body, String token) {
        try {
            webClientBuilder.build()
                    .post()
                    .uri(url)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .bodyValue(body)
                    .retrieve()
                    .toBodilessEntity()
                    .block();
        } catch (WebClientException e) {
            throw new RuntimeException("Failed to communicate with service at: " + url, e);
        }
    }

    public boolean authenticate(String username, String password) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        return userOpt.map(user -> passwordEncoder.matches(password, user.getPassword())).orElse(false);
    }
}
