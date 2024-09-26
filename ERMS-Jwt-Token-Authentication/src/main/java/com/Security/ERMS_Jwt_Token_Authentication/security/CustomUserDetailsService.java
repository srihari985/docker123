package com.Security.ERMS_Jwt_Token_Authentication.security;


import com.Security.ERMS_Jwt_Token_Authentication.Orgnization.Organization;
import com.Security.ERMS_Jwt_Token_Authentication.Orgnization.OrganizationRepository;
import com.Security.ERMS_Jwt_Token_Authentication.admin.Admin;
import com.Security.ERMS_Jwt_Token_Authentication.admin.AdminRepository;
import com.Security.ERMS_Jwt_Token_Authentication.managers.ManagerRepository;
import com.Security.ERMS_Jwt_Token_Authentication.managers.Managers;
import com.Security.ERMS_Jwt_Token_Authentication.saleManager.SaleManager;
import com.Security.ERMS_Jwt_Token_Authentication.saleManager.SaleManagerRepository;
import com.Security.ERMS_Jwt_Token_Authentication.technician.Technician;
import com.Security.ERMS_Jwt_Token_Authentication.technician.TechnicianRepository;
import com.Security.ERMS_Jwt_Token_Authentication.sales.Sales;
import com.Security.ERMS_Jwt_Token_Authentication.sales.SalesRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;


@Service
public class CustomUserDetailsService implements UserDetailsService {

    private  final OrganizationRepository organizationRepository;
    private final AdminRepository adminRepository;
    private final ManagerRepository managerRepository;
    private final SaleManagerRepository saleManagerRepository;
    private final TechnicianRepository technicianRepository;
    private final SalesRepository salesRepository;

    @Autowired
    public CustomUserDetailsService(OrganizationRepository organizationRepository, AdminRepository adminRepository,
                                    ManagerRepository managerRepository,
                                    SaleManagerRepository saleManagerRepository,
                                    TechnicianRepository technicianRepository,
                                    SalesRepository salesRepository) {
        this.organizationRepository = organizationRepository;
        this.adminRepository = adminRepository;
        this.managerRepository = managerRepository;
        this.saleManagerRepository = saleManagerRepository;
        this.technicianRepository = technicianRepository;
        this.salesRepository = salesRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<Organization> orgOpt = organizationRepository.findByEmail(username);
        if (orgOpt.isPresent()) {
            return new CustomUserDetails(orgOpt.get());
        }


        Optional<Admin> adminOpt = adminRepository.findByEmail(username);
        if (adminOpt.isPresent()) {
            return new CustomUserDetails(adminOpt.get());
        }

        Optional<Managers> managerOpt = managerRepository.findByEmail(username);
        if (managerOpt.isPresent()) {
            return new CustomUserDetails(managerOpt.get());
        }

        Optional<SaleManager> saleManagerOpt = saleManagerRepository.findByEmail(username);
        if (saleManagerOpt.isPresent()) {
            return new CustomUserDetails(saleManagerOpt.get());
        }

        Optional<Technician> technicianOpt = technicianRepository.findByEmail(username);
        if (technicianOpt.isPresent()) {
            return new CustomUserDetails(technicianOpt.get());
        }

        Optional<Sales> salesOpt = salesRepository.findByEmail(username);
        if (salesOpt.isPresent()) {
            return new CustomUserDetails(salesOpt.get());
        }

        throw new UsernameNotFoundException("User not found with email: " + username);
    }
}
