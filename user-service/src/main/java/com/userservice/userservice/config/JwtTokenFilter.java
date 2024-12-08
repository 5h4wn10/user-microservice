package com.userservice.userservice.config;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                Claims claims = jwtTokenUtil.validateToken(token);
                String role = (String) claims.get("role");
                String subject = claims.getSubject(); // Hämta subject från token
                System.out.println("Token Role: " + role);
                System.out.println("Token Subject: " + subject);

                if ("user-service".equals(subject)) {
                    // Inter-service token - tilldelas ROLE_INTERNAL
                    SecurityContextHolder.getContext().setAuthentication(
                            new UsernamePasswordAuthenticationToken(subject, null,
                                    List.of(new SimpleGrantedAuthority("ROLE_INTERNAL"))));
                } else if ("ROLE_DOCTOR".equals(role) || "ROLE_PATIENT".equals(role) || "ROLE_STAFF".equals(role)) {
                    // Vanlig användartoken
                    SecurityContextHolder.getContext().setAuthentication(
                            new UsernamePasswordAuthenticationToken(subject, null,
                                    List.of(new SimpleGrantedAuthority(role))));
                } else {
                    throw new RuntimeException("Unauthorized role: " + role);
                }

            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid JWT Token: " + e.getMessage());
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
