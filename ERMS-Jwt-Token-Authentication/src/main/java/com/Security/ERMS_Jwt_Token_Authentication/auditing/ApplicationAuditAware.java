package com.Security.ERMS_Jwt_Token_Authentication.auditing;

import com.Security.ERMS_Jwt_Token_Authentication.admin.Admin;
import com.Security.ERMS_Jwt_Token_Authentication.managers.Managers;
import com.Security.ERMS_Jwt_Token_Authentication.saleManager.SaleManager;
import com.Security.ERMS_Jwt_Token_Authentication.technician.Technician;
import com.Security.ERMS_Jwt_Token_Authentication.sales.Sales;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public class ApplicationAuditAware implements AuditorAware<String> {

    @Override
    public Optional<String> getCurrentAuditor() {
        Authentication authentication =
                SecurityContextHolder
                        .getContext()
                        .getAuthentication();

        if (authentication == null ||
                !authentication.isAuthenticated() ||
                authentication instanceof AnonymousAuthenticationToken
        ) {
            return Optional.empty();
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof Admin) {
            Admin admin = (Admin) principal;
            return Optional.ofNullable(String.valueOf(admin.getId()));  // Convert Long to String
        } else if (principal instanceof Managers) {
            Managers manager = (Managers) principal;
            return Optional.ofNullable(String.valueOf(manager.getId()));  // Convert Long to String
        } else if (principal instanceof SaleManager) {
            SaleManager saleManager = (SaleManager) principal;
            return Optional.ofNullable(String.valueOf(saleManager.getId()));  // Convert Long to String
        } else if (principal instanceof Technician) {
            Technician technician = (Technician) principal;
            return Optional.ofNullable(String.valueOf(technician.getId()));  // Convert Long to String
        } else if (principal instanceof Sales) {
            Sales sales = (Sales) principal;
            return Optional.ofNullable(String.valueOf(sales.getId()));  // Convert Long to String
        }

        return Optional.empty();
    }
}
