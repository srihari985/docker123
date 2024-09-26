package com.Security.ERMS_Jwt_Token_Authentication.Orgnization;

import com.Security.ERMS_Jwt_Token_Authentication.auth.AuthenticationRequest;
import com.Security.ERMS_Jwt_Token_Authentication.auth.AuthenticationResponse;
import com.Security.ERMS_Jwt_Token_Authentication.auth.AuthenticationService;
import com.Security.ERMS_Jwt_Token_Authentication.auth.RegisterRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth/organize")
//@PreAuthorize("hasRole('ORGANIZATION')")
public class OrganizationController {

    private  final AuthenticationService authenticationService;
    private final OrganizationService organizationService;

    public OrganizationController(AuthenticationService authenticationService, OrganizationService organizationService) {
        this.authenticationService = authenticationService;
        this.organizationService = organizationService;
    }

//    @PreAuthorize("hasAuthority('organization:create')")
    @PostMapping("/register/organization")
    public ResponseEntity<Organization> registerOrganization(@RequestBody OrganizationRequest organizationRequest) {
        Organization organization = organizationService.registerOrganization(organizationRequest);
        return ResponseEntity.ok(organization);
    }

    @PostMapping("/register/admin")
    public ResponseEntity<AuthenticationResponse> registerAdmin(@RequestBody RegisterRequest request) {
        try {
            AuthenticationResponse response = authenticationService.registerAdmin(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new AuthenticationResponse(e.getMessage()));
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<OrganizationResponse> authenticateOrganization(@RequestBody AuthenticationRequest authenticationRequest) {
        try {
            OrganizationResponse response = organizationService.authenticate(authenticationRequest);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            // Return a bad request with the error message
            return ResponseEntity.badRequest().body(new OrganizationResponse(e.getMessage()));
        }
    }


}
