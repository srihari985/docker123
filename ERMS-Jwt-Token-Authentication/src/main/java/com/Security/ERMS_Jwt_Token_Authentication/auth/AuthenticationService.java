package com.Security.ERMS_Jwt_Token_Authentication.auth;

import com.Security.ERMS_Jwt_Token_Authentication.Orgnization.Organization;
import com.Security.ERMS_Jwt_Token_Authentication.Orgnization.OrganizationRepository;
import com.Security.ERMS_Jwt_Token_Authentication.admin.Admin;
import com.Security.ERMS_Jwt_Token_Authentication.admin.AdminRepository;
import com.Security.ERMS_Jwt_Token_Authentication.managers.ManagerRepository;
import com.Security.ERMS_Jwt_Token_Authentication.managers.Managers;

import com.Security.ERMS_Jwt_Token_Authentication.saleManager.SaleManager;
import com.Security.ERMS_Jwt_Token_Authentication.saleManager.SaleManagerRepository;
import com.Security.ERMS_Jwt_Token_Authentication.sales.Sales;
import com.Security.ERMS_Jwt_Token_Authentication.sales.SalesRepository;
import com.Security.ERMS_Jwt_Token_Authentication.security.CustomUserDetails;
import com.Security.ERMS_Jwt_Token_Authentication.security.CustomUserDetailsService;
import com.Security.ERMS_Jwt_Token_Authentication.technician.Technician;
import com.Security.ERMS_Jwt_Token_Authentication.technician.TechnicianRepository;
import com.Security.ERMS_Jwt_Token_Authentication.token.Token;
import com.Security.ERMS_Jwt_Token_Authentication.token.TokenRepository;
import com.Security.ERMS_Jwt_Token_Authentication.token.TokenType;
import com.Security.ERMS_Jwt_Token_Authentication.config.JwtService;
import com.Security.ERMS_Jwt_Token_Authentication.user.Role;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.cert.Extension;
import java.util.List;
import java.util.Optional;

@Service
public class AuthenticationService {

    private final AdminRepository adminRepository;
    private final ManagerRepository managerRepository;
    private final SaleManagerRepository saleManagerRepository;
    private final TechnicianRepository technicianRepository;
    private final SalesRepository salesRepository;
    private final TokenRepository tokenRepository;
    private final OrganizationRepository organizationRepository; // Add this
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService customUserDetailsService;

    public AuthenticationService(AdminRepository adminRepository,
                                 ManagerRepository managerRepository,
                                 SaleManagerRepository saleManagerRepository,
                                 TechnicianRepository technicianRepository,
                                 SalesRepository salesRepository,
                                 TokenRepository tokenRepository,
                                 OrganizationRepository organizationRepository, // Add this
                                 PasswordEncoder passwordEncoder,
                                 JwtService jwtService,
                                 AuthenticationManager authenticationManager, CustomUserDetailsService customUserDetailsService) {
        this.adminRepository = adminRepository;
        this.managerRepository = managerRepository;
        this.saleManagerRepository = saleManagerRepository;
        this.technicianRepository = technicianRepository;
        this.salesRepository = salesRepository;
        this.tokenRepository = tokenRepository;
        this.organizationRepository = organizationRepository; // Add this
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.customUserDetailsService = customUserDetailsService;
    }

    // Register Method

    public AuthenticationResponse registerAdmin(RegisterRequest request) {
        Organization organization = organizationRepository.findByOrganizationId(request.getOrganizationId())
                .orElseThrow(() -> new IllegalArgumentException("Invalid organization ID"));

        // Check if the email is already in use
        if (adminRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email is already in use");
        }

        Admin admin = new Admin();
        setUserDetails(admin, request);
        admin.setOrganization(organization); // Set the organization
        adminRepository.save(admin); // Save admin details in Admin table
        return generateJwtResponse(admin);
    }


    public AuthenticationResponse registerManager(RegisterRequest request) {
        // Verify the admin or organization before proceeding
        Admin admin = adminRepository.findByAdminId(request.getAdminId())
                .orElseThrow(() -> new IllegalArgumentException("Invalid admin ID"));

        // Check if the email is already in use
        if (managerRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email is already in use");
        }

        Managers manager = new Managers();
        setUserDetails(manager, request);
        manager.setAdmin(admin); // Link the manager to the respective admin
        managerRepository.save(manager); // Save manager details in Manager table
        return generateJwtResponse(manager);
    }


    public AuthenticationResponse registerSaleManager(RegisterRequest request) {
        Managers manager = managerRepository.findByManagersId(request.getManagersId())
                .orElseThrow(() -> new IllegalArgumentException("Invalid manager ID"));

        if (saleManagerRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email is already in use");
        }

        SaleManager saleManager = new SaleManager();
        setUserDetails(saleManager, request);
        saleManager.setManager(manager);
        saleManagerRepository.save(saleManager);
        return generateJwtResponse(saleManager);
    }



    public AuthenticationResponse registerTechnician(RegisterRequest request) {
        // Find SaleManager by the custom saleManagerId (String)
        SaleManager saleManager = saleManagerRepository.findBySaleManagerId(request.getSaleManagerId())
                .orElseThrow(() -> new IllegalArgumentException("Invalid sale manager ID"));

        // Check if the email is already in use
        if (technicianRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email is already in use");
        }

        // Create and save Technician
        Technician technician = new Technician();
        setUserDetails(technician, request);
        technician.setSaleManager(saleManager);
        technicianRepository.save(technician);

        return generateJwtResponse(technician);
    }

    public AuthenticationResponse registerSales(RegisterRequest request) {
        // Find SaleManager by the custom saleManagerId (String)
        SaleManager saleManager = saleManagerRepository.findBySaleManagerId(request.getSaleManagerId())
                .orElseThrow(() -> new IllegalArgumentException("Invalid sale manager ID"));

        // Check if the email is already in use
        if (salesRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email is already in use");
        }

        // Create and save Sales
        Sales sales = new Sales();
        setUserDetails(sales, request);
        sales.setSaleManager(saleManager);
        salesRepository.save(sales);

        return generateJwtResponse(sales);
    }



    // Set User Details

    private void setUserDetails(Object user, RegisterRequest request) {
        if (user instanceof Admin) {
            Admin admin = (Admin) user;
            admin.setFirstname(request.getFirstname());
            admin.setLastname(request.getLastname());
            admin.setEmail(request.getEmail());
            admin.setPassword(passwordEncoder.encode(request.getPassword()));
            admin.setRole(request.getRole());
            admin.setAdminId(generateUserRoleId(request.getRole()));
        } else if (user instanceof Managers) {
            Managers manager = (Managers) user;
            manager.setFirstname(request.getFirstname());
            manager.setLastname(request.getLastname());
            manager.setEmail(request.getEmail());
            manager.setPassword(passwordEncoder.encode(request.getPassword()));
            manager.setRole(request.getRole());
            manager.setManagersId(generateUserRoleId(request.getRole()));
        } else if (user instanceof SaleManager) {
            SaleManager saleManager = (SaleManager) user;
            saleManager.setFirstname(request.getFirstname());
            saleManager.setLastname(request.getLastname());
            saleManager.setEmail(request.getEmail());
            saleManager.setPassword(passwordEncoder.encode(request.getPassword()));
            saleManager.setRole(request.getRole());
            saleManager.setSaleManagerId(generateUserRoleId(request.getRole()));
        } else if (user instanceof Technician) {
            Technician technician = (Technician) user;
            technician.setFirstname(request.getFirstname());
            technician.setLastname(request.getLastname());
            technician.setEmail(request.getEmail());
            technician.setPassword(passwordEncoder.encode(request.getPassword()));
            technician.setRole(request.getRole());
            technician.setSaleManagerTechnicianId(generateUserRoleId(request.getRole()));
        } else if (user instanceof Sales) {
            Sales sales = (Sales) user;
            sales.setFirstname(request.getFirstname());
            sales.setLastname(request.getLastname());
            sales.setEmail(request.getEmail());
            sales.setPassword(passwordEncoder.encode(request.getPassword()));
            sales.setRole(request.getRole());
            sales.setSaleManagerSalesId(generateUserRoleId(request.getRole()));
        }
    }


    // Generate JWT Response

    private AuthenticationResponse generateJwtResponse(Object user) {
        UserDetails userDetails;
        if (user instanceof Organization){
            userDetails = new CustomUserDetails((Organization) user);
        }
        else if (user instanceof Admin) {
            userDetails = new CustomUserDetails((Admin) user);
        } else if (user instanceof Managers) {
            userDetails = new CustomUserDetails((Managers) user);
        } else if (user instanceof SaleManager) {
            userDetails = new CustomUserDetails((SaleManager) user);
        } else if (user instanceof Technician) {
            userDetails = new CustomUserDetails((Technician) user);
        } else if (user instanceof Sales) {
            userDetails = new CustomUserDetails((Sales) user);
        } else {
            throw new IllegalArgumentException("Invalid user type");
        }

        String jwtToken = jwtService.generateToken(userDetails);
        String refreshToken = jwtService.generateRefreshToken(userDetails);
        saveUserToken(user, jwtToken);
        return new AuthenticationResponse(jwtToken, refreshToken);
    }


    // Authenticate  Method

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(request.getEmail());
        String jwtToken = jwtService.generateToken(userDetails);
        String refreshToken = jwtService.generateRefreshToken(userDetails);
        revokeAllUserTokens(userDetails);  // Update to accept UserDetails
        saveUserToken(userDetails, jwtToken);
        return new AuthenticationResponse(jwtToken, refreshToken);
    }


    // Other helper methods like findUserByEmail, saveUserToken, revokeAllUserTokens,
    // refreshToken and generateUserRoleId etc.

    private Object findUserByEmail(String email) {
        Optional<Organization> organization = organizationRepository.findByEmail(email);
        if (organization.isPresent()) return organization.get();

        Optional<Admin> admin = adminRepository.findByEmail(email);
        if (admin.isPresent()) return admin.get();

        Optional<Managers> manager = managerRepository.findByEmail(email);
        if (manager.isPresent()) return manager.get();

        Optional<SaleManager> saleManager = saleManagerRepository.findByEmail(email);
        if (saleManager.isPresent()) return saleManager.get();

        Optional<Technician> technician = technicianRepository.findByEmail(email);
        if (technician.isPresent()) return technician.get();

        Optional<Sales> sales = salesRepository.findByEmail(email);
        if (sales.isPresent()) return sales.get();

        throw new IllegalArgumentException("User not found");
    }


    private void saveUserToken(Object user, String jwtToken) {
        Token token = new Token();
        token.setToken(jwtToken);
        token.setTokenType(TokenType.BEARER);
        token.setExpired(false);
        token.setRevoked(false);
        if (user instanceof CustomUserDetails) {
            token.setUser(((CustomUserDetails) user).getUser());
        }
        tokenRepository.save(token);
    }


    private void revokeAllUserTokens(UserDetails userDetails) {
        List<Token> validUserTokens = tokenRepository.findAllValidTokensByUser(getUserId(userDetails));
        if (validUserTokens.isEmpty()) return;

        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }


    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Extract refresh token from request header
        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Refresh token is missing or malformed");
        }

        final String refreshToken = authHeader.substring(7);
        String email = jwtService.extractUsername(refreshToken); // Assuming the refresh token contains the username

        if (email != null) {
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(email);

            // Validate the refresh token
            if (jwtService.isTokenValid(refreshToken, userDetails)) {
                String newAccessToken = jwtService.generateToken(userDetails);
                String newRefreshToken = jwtService.generateRefreshToken(userDetails);

                // Revoke all previous tokens and save the new tokens
                revokeAllUserTokens(userDetails);
                saveUserToken(userDetails, newAccessToken);

                // Send the new tokens back to the client in the response
                AuthenticationResponse authResponse = new AuthenticationResponse(newAccessToken, newRefreshToken);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            } else {
                throw new IllegalArgumentException("Invalid refresh token");
            }
        }
    }



    private Integer getUserId(UserDetails userDetails) {
        String email = userDetails.getUsername();
        // Use the repositories to get the user ID based on email
        if (adminRepository.findByEmail(email).isPresent()) {
            return Math.toIntExact(adminRepository.findByEmail(email).get().getId());
        } else if (managerRepository.findByEmail(email).isPresent()) {
            return Math.toIntExact(managerRepository.findByEmail(email).get().getId());
        } else if (saleManagerRepository.findByEmail(email).isPresent()) {
            return Math.toIntExact(saleManagerRepository.findByEmail(email).get().getId());
        } else if (technicianRepository.findByEmail(email).isPresent()) {
            return Math.toIntExact(technicianRepository.findByEmail(email).get().getId());
        } else if (salesRepository.findByEmail(email).isPresent()) {
            return Math.toIntExact(salesRepository.findByEmail(email).get().getId());
        }
        throw new IllegalArgumentException("User not found");
    }

    public String generateUserRoleId(Role role) {
        String prefix;
        List<String> lastRoleIdList;
        Pageable pageable = PageRequest.of(0, 1);  // Fetch only the latest record

        // Determine the prefix and get the last role ID from the respective repository
        switch (role) {
            case ORGANIZATION:
                prefix = "ORG";
                lastRoleIdList = organizationRepository.findUserRoleIdByRole(pageable);
                break;
            case ADMIN:
                prefix = "ADM";
                lastRoleIdList = adminRepository.findUserRoleIdByRole(pageable);
                break;
            case MANAGER:
                prefix = "MAN";
                lastRoleIdList = managerRepository.findUserRoleIdByRole(pageable);
                break;
            case SALE_MANAGER:
                prefix = "SMAN";
                lastRoleIdList = saleManagerRepository.findUserRoleIdByRole(pageable);
                break;
            case TECHNICIAN:
                prefix = "TECH";
                lastRoleIdList = technicianRepository.findUserRoleIdByRole(pageable);
                break;
            case SALES:
                prefix = "SALES";
                lastRoleIdList = salesRepository.findUserRoleIdByRole(pageable);
                break;
            default:
                throw new IllegalArgumentException("Unknown role: " + role);
        }

        // Determine the next ID number (default is 1)
        int nextId = 1;
        if (!lastRoleIdList.isEmpty()) {
            String lastRoleId = lastRoleIdList.get(0);
            String numericPart = lastRoleId.replace(prefix + "-", "");  // Extract the numeric part

            // Safely parse the numeric part
            try {
                nextId = Integer.parseInt(numericPart) + 1;  // Increment the number
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid numeric part in the last role ID: " + lastRoleId);
            }
        }

        // Format and return the new userRoleId with leading zeros (e.g., ADM-001)
        return String.format("%s-%03d", prefix, nextId);
    }




}
