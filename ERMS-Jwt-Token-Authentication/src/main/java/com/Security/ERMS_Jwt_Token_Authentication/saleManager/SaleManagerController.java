package com.Security.ERMS_Jwt_Token_Authentication.saleManager;


import com.Security.ERMS_Jwt_Token_Authentication.auth.AuthenticationResponse;
import com.Security.ERMS_Jwt_Token_Authentication.auth.AuthenticationService;
import com.Security.ERMS_Jwt_Token_Authentication.auth.RegisterRequest;
import com.Security.ERMS_Jwt_Token_Authentication.user.ChangePasswordRequest;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/saleManagement")
@Tag(name = "SaleManager")
public class SaleManagerController {

    private final AuthenticationService authenticationService;

    public SaleManagerController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }


    @PostMapping("/register/technician")
    public ResponseEntity<AuthenticationResponse> registerTechnician(@RequestBody RegisterRequest request) {
        try {
            AuthenticationResponse response = authenticationService.registerTechnician(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new AuthenticationResponse(e.getMessage()));
        }
    }

    @PostMapping("/register/sales")
    public ResponseEntity<AuthenticationResponse> registerSales(@RequestBody RegisterRequest request) {
        try {
            AuthenticationResponse response = authenticationService.registerSales(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new AuthenticationResponse(e.getMessage()));
        }
    }



//    @GetMapping
//    public String get() {
//        return "GET:: saleManagement controller";
//    }
//    @PostMapping
//    public String post() {
//        return "POST:: saleManagement controller";
//    }
//    @PutMapping
//    public String put() {
//        return "PUT:: saleManagement controller";
//    }
//    @DeleteMapping
//    public String delete() {
//        return "DELETE:: saleManagement controller";
//    }


}
