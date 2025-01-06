package com.userservice.userservice.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.stream.Collectors;

public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        var realmAccess = (Collection<String>) jwt.getClaimAsMap("realm_access").get("roles");


        System.out.println("Mapped Roles: " + realmAccess); // Debug-logg

        return realmAccess.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .collect(Collectors.toList());
    }

    /*HEJ TEST GIT ACTIONS*/
}
