package com.Security.ERMS_Jwt_Token_Authentication.Orgnization;

import com.Security.ERMS_Jwt_Token_Authentication.auth.AuthenticationRequest;
import com.Security.ERMS_Jwt_Token_Authentication.auth.AuthenticationResponse;
import com.Security.ERMS_Jwt_Token_Authentication.auth.AuthenticationService;
import com.Security.ERMS_Jwt_Token_Authentication.security.CustomUserDetailsService;
import com.Security.ERMS_Jwt_Token_Authentication.user.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class OrganizationService {

    private final AuthenticationService authenticationService;
    private final PasswordEncoder passwordEncoder;
    private final OrganizationRepository organizationRepository;
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService customUserDetailsService;

    @Autowired
    public OrganizationService(AuthenticationService authenticationService, PasswordEncoder passwordEncoder, OrganizationRepository organizationRepository, AuthenticationManager authenticationManager, CustomUserDetailsService customUserDetailsService) {
        this.authenticationService = authenticationService;
        this.passwordEncoder = passwordEncoder;
        this.organizationRepository = organizationRepository;
        this.authenticationManager = authenticationManager;
        this.customUserDetailsService = customUserDetailsService;
    }

    // Method to register an organization
    public Organization registerOrganization(OrganizationRequest organizationRequest) {

        // Check if the organization already exists by email
        if (organizationRepository.existsByEmail(organizationRequest.getEmail())) {
            throw new IllegalArgumentException("Organization with this email already exists");
        }

        // Ensure password is not empty or null
        if (organizationRequest.getPassword() == null || organizationRequest.getPassword().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }

        Organization organization = new Organization();
        // ID will be auto-generated by the repository
        organization.setName(organizationRequest.getName());
        organization.setEmail(organizationRequest.getEmail());
        organization.setPassword(passwordEncoder.encode(organizationRequest.getPassword()));
        organization.setRole(organizationRequest.getRole()); // Set role first
        organization.setOrganizationId(authenticationService.generateUserRoleId(organizationRequest.getRole()));
        organization.setAddress(organizationRequest.getAddress());

        // Save the organization to the database
        return organizationRepository.save(organization);
    }


    // Method to authenticate without JWT token
    public OrganizationResponse authenticate(AuthenticationRequest request) {
        // Check if the organization exists by email
        Optional<Organization> organizationOpt = organizationRepository.findByEmail(request.getEmail());
        if (organizationOpt.isEmpty()) {
            throw new IllegalArgumentException("Invalid email or password");
        }

        Organization organization = organizationOpt.get();

        // Verify if the provided password matches the stored password
        if (!passwordEncoder.matches(request.getPassword(), organization.getPassword())) {
            throw new IllegalArgumentException("Invalid email or password");
        }

        // Authentication successful
        return new OrganizationResponse("Authentication successful for organization: " + organization.getName());
    }



}