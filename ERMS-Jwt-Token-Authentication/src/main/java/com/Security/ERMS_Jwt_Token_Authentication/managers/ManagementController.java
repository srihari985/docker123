package com.Security.ERMS_Jwt_Token_Authentication.managers;


import com.Security.ERMS_Jwt_Token_Authentication.auth.AuthenticationResponse;
import com.Security.ERMS_Jwt_Token_Authentication.auth.AuthenticationService;
import com.Security.ERMS_Jwt_Token_Authentication.auth.RegisterRequest;
import com.Security.ERMS_Jwt_Token_Authentication.user.ChangePasswordRequest;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/management")
@Tag(name = "Management")
public class ManagementController {


    private final AuthenticationService authenticationService;

    public ManagementController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }



    @PostMapping("/register/saleManager")
    public ResponseEntity<AuthenticationResponse> registerSaleManager(@RequestBody RegisterRequest request) {
        try {
            AuthenticationResponse response = authenticationService.registerSaleManager(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new AuthenticationResponse(e.getMessage()));
        }
    }


//    @GetMapping
//    public String get() {
//        return "GET:: management controller";
//    }
//    @PostMapping
//    public String post() {
//        return "POST:: management controller";
//    }
//    @PutMapping
//    public String put() {
//        return "PUT:: management controller";
//    }
//    @DeleteMapping
//    public String delete() {
//        return "DELETE:: management controller";
//    }



}
