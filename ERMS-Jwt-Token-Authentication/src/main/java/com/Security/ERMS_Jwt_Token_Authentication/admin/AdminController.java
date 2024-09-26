package com.Security.ERMS_Jwt_Token_Authentication.admin;

import com.Security.ERMS_Jwt_Token_Authentication.auth.AuthenticationResponse;
import com.Security.ERMS_Jwt_Token_Authentication.auth.AuthenticationService;
import com.Security.ERMS_Jwt_Token_Authentication.auth.RegisterRequest;
import com.Security.ERMS_Jwt_Token_Authentication.user.ChangePasswordRequest;
import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {

    private final AuthenticationService authenticationService;

    public AdminController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }


    @PostMapping("/register/manager")
    public ResponseEntity<AuthenticationResponse> registerManager(@RequestBody RegisterRequest request) {
        try {
            AuthenticationResponse response = authenticationService.registerManager(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new AuthenticationResponse(e.getMessage()));
        }
    }


//
//    @GetMapping
//    public String get() {
//        return "GET:: admin controller";
//    }
//
//    @PostMapping
//    public String post() {
//        return "POST:: admin controller";
//    }
//    @PutMapping
//    public String put() {
//        return "PUT:: admin controller";
//    }
//    @DeleteMapping
//    public String delete() {
//        return "DELETE:: admin controller";
//    }

}
