package com.userservice;

import com.userservice.userservice.UserServiceApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

package com.userservice.userservice.service;

import com.userservice.userservice.dto.PatientDTO;
import com.userservice.userservice.dto.UserDTO;
import com.userservice.userservice.model.Role;
import com.userservice.userservice.model.User;
import com.userservice.userservice.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UserServiceTest {

    @InjectMocks
    private UserService userService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private WebClient.Builder webClientBuilder;

    @Mock
    private WebClient webClient;

    @Mock
    private WebClient.RequestHeadersUriSpec<?> requestHeadersUriSpec;

    @Mock
    private WebClient.ResponseSpec responseSpec;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testGetAllUsers() {
        // Arrange
        User user1 = new User(1L, "user1", "User One", Role.PATIENT);
        User user2 = new User(2L, "user2", "User Two", Role.DOCTOR);
        when(userRepository.findAll()).thenReturn(Arrays.asList(user1, user2));

        // Act
        List<UserDTO> users = userService.getAllUsers();

        // Assert
        assertEquals(2, users.size());
        assertEquals("user1", users.get(0).getUsername());
        assertEquals("User Two", users.get(1).getFullName());
    }

    @Test
    void testGetUserById() {
        // Arrange
        User user = new User(1L, "user1", "User One", Role.PATIENT);
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        // Act
        UserDTO userDTO = userService.getUserById(1L);

        // Assert
        assertNotNull(userDTO);
        assertEquals("user1", userDTO.getUsername());
    }

    @Test
    void testCreateUser() {
        // Arrange
        User user = new User(null, "user1", "User One", Role.PATIENT);
        User savedUser = new User(1L, "user1", "User One", Role.PATIENT);
        when(userRepository.save(user)).thenReturn(savedUser);

        // Act
        User result = userService.createUser(user);

        // Assert
        assertNotNull(result);
        assertEquals(1L, result.getId());
    }

    @Test
    void testGetPatientDetails() {
        // Arrange
        PatientDTO patientDTO = new PatientDTO(1L, "Patient One", "Details");
        when(webClientBuilder.build()).thenReturn(webClient);
        when(webClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri("http://patient-service/1")).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(PatientDTO.class)).thenReturn(WebClient.create().post().bodyValue(patientDTO).retrieve().bodyToMono(PatientDTO.class));

        // Act
        PatientDTO result = userService.getPatientDetails(1L);

        // Assert
        assertNotNull(result);
        assertEquals("Patient One", result.getName());
    }

    @Test
    void testGetUserByUsername() {
        // Arrange
        User user = new User(1L, "user1", "User One", Role.PATIENT);
        when(userRepository.findByUsername("user1")).thenReturn(Optional.of(user));

        // Act
        UserDTO userDTO = userService.getUserByUsername("user1");

        // Assert
        assertNotNull(userDTO);
        assertEquals("User One", userDTO.getFullName());
    }

    @Test
    void testIsPatient() {
        // Arrange
        User user = new User(1L, "user1", "User One", Role.PATIENT);
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        // Act
        boolean isPatient = userService.isPatient(1L);

        // Assert
        assertTrue(isPatient);
    }

    @Test
    void testIsPractitioner() {
        // Arrange
        User user = new User(1L, "user2", "User Two", Role.DOCTOR);
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        // Act
        boolean isPractitioner = userService.isPractitioner(1L);

        // Assert
        assertTrue(isPractitioner);
    }

    @Test
    void testGetPatientDetailsFails() {
        // Arrange
        when(webClientBuilder.build()).thenReturn(webClient);
        when(webClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri(anyString())).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.retrieve()).thenThrow(WebClientResponseException.class);

        // Act & Assert
        assertThrows(RuntimeException.class, () -> userService.getPatientDetails(1L));
    }
}

