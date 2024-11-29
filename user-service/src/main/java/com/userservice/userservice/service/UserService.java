package com.userservice.userservice.service;

import com.userservice.userservice.dto.PatientDTO;
import com.userservice.userservice.dto.UserDTO;
import com.userservice.userservice.model.Role;
import com.userservice.userservice.model.User;
import com.userservice.userservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientException;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private WebClient.Builder webClientBuilder;

    @Value("${patient.service.url}")
    private String patientServiceUrl;

    @Value("${practitioner.service.url}")
    private String practitionerServiceUrl;

    // Fetch all users
    public List<UserDTO> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::toDTO)
                .collect(Collectors.toList());
    }

    // Fetch user by ID
    public UserDTO getUserById(Long id) {
        return userRepository.findById(id)
                .map(this::toDTO)
                .orElse(null);
    }





    public UserDTO getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found with username: " + username));

        return new UserDTO(
                user.getId(),
                user.getFullName(),
                user.getUsername(),
                user.getRole()
        );
    }

    public User findUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }

    // Create a new user
    public User createUser(User user) {
        return userRepository.save(user);
    }

    // Delete a user
    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    // Check if user is a patient
    public boolean isPatient(Long userId) {
        UserDTO user = getUserById(userId);
        return user != null && user.getRole().equals(Role.PATIENT);
    }

    // Check if user is a practitioner
    public boolean isPractitioner(Long userId) {
        UserDTO user = getUserById(userId);
        return user != null && (user.getRole().equals(Role.DOCTOR) || user.getRole().equals(Role.STAFF));
    }

    // Fetch all patients
    public List<UserDTO> getAllPatientsAsDTO() {
        return userRepository.findAll().stream()
                .filter(user -> user.getRole().equals(Role.PATIENT)) // Kontrollera rollen direkt
                .map(this::toDTO)
                .collect(Collectors.toList());
    }//SKA TAS BORT KANSKE FÖR DECENTRIALISERING

    // Fetch all practitioners
    public List<UserDTO> getAllPractitionersAsDTO() {
        return userRepository.findAll().stream()
                .filter(user -> user.getRole().equals(Role.DOCTOR) || user.getRole().equals(Role.STAFF)) // Kontrollera rollerna
                .map(this::toDTO)
                .collect(Collectors.toList());
    }//SKA TAS BORT KANSKE FÖR DECENTRIALISERING

    // Get patient details from patient-service
    public PatientDTO getPatientDetails(Long userId) {
        try {
            System.out.println("Fetching patient details for userId: {}" + userId);
            return webClientBuilder.build()
                    .get()
                    .uri(patientServiceUrl + "/" + userId)
                    .retrieve()
                    .bodyToMono(PatientDTO.class)
                    .block();
        } catch (WebClientException e) {
            throw new RuntimeException("Failed to fetch patient details", e);
        }
    }

    // Helper method to convert User to DTO
    public UserDTO toDTO(User user) {
        return new UserDTO(
                user.getId(),
                user.getUsername(),
                user.getFullName(),
                user.getRole()
        );
    }
}
