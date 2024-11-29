package com.userservice.userservice.dto;

import com.userservice.userservice.model.Role;

public class PractitionerDTO {
    private Long userId;
    private String name;
    private String specialty;
    private Role role;

    public PractitionerDTO(Long userId, String name, String specialty, Role role) {
        this.userId = userId;
        this.name = name;
        this.specialty = specialty;
        this.role = role;
    }

    public PractitionerDTO(){}

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSpecialty() {
        return specialty;
    }

    public void setSpecialty(String specialty) {
        this.specialty = specialty;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }
}
