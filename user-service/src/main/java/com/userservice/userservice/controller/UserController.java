package com.userservice.userservice.controller;

import com.userservice.userservice.dto.AuthDTO;
import com.userservice.userservice.dto.PatientDTO;
import com.userservice.userservice.dto.UserDTO;
import com.userservice.userservice.model.User;
import com.userservice.userservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;





    //POOOOOOOOOOOOOOOOOST MAPPERS


    // Create a new user
    @PostMapping
    public ResponseEntity<User> createUser(@RequestBody User user) {
        User savedUser = userService.createUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedUser);
    }

    // Delete a user
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }





    //GEEEEEEEEEEEEEEET MAPPERS

    // Get all users
    @GetMapping
    public ResponseEntity<List<UserDTO>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    // Get all patients
    @GetMapping("/patients")
    //@PreAuthorize("hasAnyAuthority('DOCTOR', 'STAFF')")
    public ResponseEntity<List<UserDTO>> getAllPatients() {
        return ResponseEntity.ok(userService.getAllPatientsAsDTO());
        //return ResponseEntity.ok(userService.getUsersByRole(Role.valueOf("PATIENT")));

    }

    // Get all practitioners
    @GetMapping("/practitioners")
    //@PreAuthorize("hasAnyRole('PATIENT', 'STAFF')")
    public ResponseEntity<List<UserDTO>> getAllPractitioners() {
        return ResponseEntity.ok(userService.getAllPractitionersAsDTO());
        //return ResponseEntity.ok(userService.getUsersByRole(Role.valueOf("PRACTITIONER")));
    }

    // Hämta en användare med ID som DTO
    @GetMapping("/{id}")
    public ResponseEntity<UserDTO> getUserById(@PathVariable Long id) {
        UserDTO user = userService.getUserById(id);
        if (user != null) {
            return ResponseEntity.ok(user);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/by-username/{username}")
    public ResponseEntity<UserDTO> getUserByUsername(@PathVariable String username) {
        UserDTO user = userService.getUserByUsername(username);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(user);
    }

    @GetMapping("/by-username2/{username}")
    public ResponseEntity<AuthDTO> getUserByUsername2(@PathVariable String username) {
        User user = userService.findUserByUsername(username);

        if (user == null) {
            return ResponseEntity.notFound().build();
        }

        // Skapa och returnera AuthDTO
        AuthDTO authDTO = new AuthDTO(user.getUsername(), user.getPassword(), user.getRole());
        return ResponseEntity.ok(authDTO);
    }


    // Get receivers (practitioners or patients based on current user's role)
    @GetMapping("/patients/receivers")
    public ResponseEntity<List<UserDTO>> getReceiversForPatients(Authentication authentication) {
        User currentUser = userService.findUserByUsername(authentication.getName());

        List<UserDTO> receivers;

        /*if (currentUser.getRole().equals("PATIENT")) {
            receivers = userService.getAllPractitionersAsDTO();
        } else if (currentUser.getRole().equals("DOCTOR") || currentUser.getRole().equals("STAFF")) {
            receivers = userService.getAllPatientsAsDTO();
        } else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }*/
        receivers = userService.getAllPractitionersAsDTO();
        return ResponseEntity.ok(receivers);
    }

    @GetMapping("/practitioners/receivers")
    public ResponseEntity<List<UserDTO>> getReceiversForPractitioners(Authentication authentication) {
        User currentUser = userService.findUserByUsername(authentication.getName());

        List<UserDTO> receivers;

        /*if (currentUser.getRole().equals("PATIENT")) {
            receivers = userService.getAllPractitionersAsDTO();
        } else if (currentUser.getRole().equals("DOCTOR") || currentUser.getRole().equals("STAFF")) {
            receivers = userService.getAllPatientsAsDTO();
        } else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }*/
        receivers = userService.getAllPatientsAsDTO();
        return ResponseEntity.ok(receivers);
    }

    // Get current user's details
    @GetMapping("/current")
    public ResponseEntity<UserDTO> getCurrentUser(Authentication authentication) {
        User currentUser = userService.findUserByUsername(authentication.getName());

        if(currentUser != null) {
            return ResponseEntity.ok(userService.toDTO(currentUser));
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    // Get patient details from patient-service
    //@PreAuthorize("hasAnyRole('DOCTOR', 'PATIENT')")
    @GetMapping("/patients/{id}")
    public ResponseEntity<PatientDTO> getPatientDetails(@PathVariable Long id) {
        PatientDTO patientDetails = userService.getPatientDetails(id);
        if (patientDetails != null) {
            return ResponseEntity.ok(patientDetails);
        } else {
            return ResponseEntity.notFound().build();
        }
    }


    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("Det funkar");
    }



}
