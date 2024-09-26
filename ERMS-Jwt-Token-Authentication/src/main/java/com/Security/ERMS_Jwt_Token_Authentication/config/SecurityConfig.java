package com.Security.ERMS_Jwt_Token_Authentication.config;


import com.Security.ERMS_Jwt_Token_Authentication.security.CustomUserDetailsService;
import com.Security.ERMS_Jwt_Token_Authentication.technician.Technician;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
//import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.Security.ERMS_Jwt_Token_Authentication.user.Permission.*;
import static com.Security.ERMS_Jwt_Token_Authentication.user.Role.*;
import static org.springframework.http.HttpMethod.*;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private static final String[] WHITE_LIST_URL = {
            "/api/v1/auth/**",
            "/api/v1/auth/logout"
    };
    private final AuthenticationProvider authenticationProvider;
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final LogoutHandler logoutHandler;


    public SecurityConfig(AuthenticationProvider authenticationProvider, JwtAuthenticationFilter jwtAuthFilter, LogoutHandler logoutHandler) {
        this.authenticationProvider = authenticationProvider;
        this.jwtAuthFilter = jwtAuthFilter;
        this.logoutHandler = logoutHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(req -> req
                                .requestMatchers(WHITE_LIST_URL).permitAll()

//                                // Organization access control
                                .requestMatchers("/api/auth/organize/**").permitAll()
//                                .requestMatchers(GET, "/api/auth/organize/**").hasAuthority(ORGANIZATION_READ.name())
//                                .requestMatchers(POST, "/api/auth/organize/**").hasAuthority(ORGANIZATION_CREATE.name())
//                                .requestMatchers(PUT, "/api/auth/organize/**").hasAuthority(ORGANIZATION_UPDATE.name())
//                                .requestMatchers(DELETE, "/api/auth/organize/**").hasAuthority(ORGANIZATION_DELETE.name())

                                // Admin access control
                                .requestMatchers("/api/v1/admin/**").hasAnyRole(ORGANIZATION.name(),ADMIN.name())
                                .requestMatchers(GET, "/api/v1/admin/**").hasAnyAuthority(ORGANIZATION_READ.name(),ADMIN_READ.name())
                                .requestMatchers(POST, "/api/v1/admin/**").hasAnyAuthority(ORGANIZATION_CREATE.name(),ADMIN_CREATE.name())
                                .requestMatchers(PUT, "/api/v1/admin/**").hasAnyAuthority(ORGANIZATION_UPDATE.name(),ADMIN_UPDATE.name())
                                .requestMatchers(DELETE, "/api/v1/admin/**").hasAnyAuthority(ORGANIZATION_DELETE.name(),ADMIN_DELETE.name())

                                // Manager access control
                                .requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(),MANAGER.name())
                                .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(),MANAGER_READ.name())
                                .requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(),MANAGER_CREATE.name())
                                .requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(),MANAGER_UPDATE.name())
                                .requestMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(),MANAGER_DELETE.name())

                                // Sale Manager and others
                                .requestMatchers("/api/v1/saleManagement/**").hasAnyRole(ADMIN.name(), MANAGER.name(),SALE_MANAGER.name())
                                .requestMatchers(GET, "/api/v1/saleManagement/**").hasAnyAuthority(MANAGER_READ.name(),ADMIN_READ.name(),SALE_MANAGER_READ.name())
                                .requestMatchers(POST, "/api/v1/saleManagement/**").hasAnyAuthority(MANAGER_CREATE.name(),ADMIN_CREATE.name(),SALE_MANAGER_CREATE.name())
                                .requestMatchers(PUT, "/api/v1/saleManagement/**").hasAnyAuthority(MANAGER_UPDATE.name(),ADMIN_UPDATE.name(),SALE_MANAGER_UPDATE.name())
                                .requestMatchers(DELETE, "/api/v1/saleManagement/**").hasAnyAuthority(MANAGER_DELETE.name(),ADMIN_DELETE.name(),SALE_MANAGER_DELETE.name())

                                // Technician
                                .requestMatchers("/api/v1/technician/**").hasAnyRole(ADMIN.name(),MANAGER.name(), SALE_MANAGER.name(),TECHNICIAN.name())
                                .requestMatchers(GET, "/api/v1/technician/**").hasAnyAuthority(TECHNICIAN_READ.name(),SALE_MANAGER_READ.name(),MANAGER_READ.name(),ADMIN_READ.name())
                                .requestMatchers(POST, "/api/v1/technician/**").hasAnyAuthority(TECHNICIAN_CREATE.name(),SALE_MANAGER_CREATE.name(),MANAGER_CREATE.name(),ADMIN_CREATE.name())
                                .requestMatchers(PUT, "/api/v1/technician/**").hasAnyAuthority(TECHNICIAN_UPDATE.name(),SALE_MANAGER_UPDATE.name(),MANAGER_UPDATE.name(),ADMIN_UPDATE.name())
                                .requestMatchers(DELETE, "/api/v1/technician/**").hasAnyAuthority(TECHNICIAN_DELETE.name(),SALE_MANAGER_DELETE.name(),MANAGER_DELETE.name(),ADMIN_DELETE.name())


                                //Sales
                                .requestMatchers("/api/v1/sales/**").hasAnyRole( ADMIN.name(),MANAGER.name(), SALE_MANAGER.name(),SALES.name())
                                .requestMatchers(GET, "/api/v1/sales/**").hasAnyAuthority(SALES_READ.name(),SALE_MANAGER_READ.name(),MANAGER_READ.name(),ADMIN_READ.name())
                                .requestMatchers(POST, "/api/v1/sales/**").hasAnyAuthority(SALES_CREATE.name(),SALE_MANAGER_CREATE.name(),MANAGER_CREATE.name(),ADMIN_CREATE.name())
                                .requestMatchers(PUT, "/api/v1/sales/**").hasAnyAuthority(SALES_UPDATE.name(),SALE_MANAGER_UPDATE.name(),MANAGER_UPDATE.name(),ADMIN_UPDATE.name())
                                .requestMatchers(DELETE, "/api/v1/sales/**").hasAnyAuthority(SALES_DELETE.name(),SALE_MANAGER_DELETE.name(),MANAGER_DELETE.name(),ADMIN_DELETE.name())


                                .anyRequest()
                                .authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout ->
                        logout.logoutUrl("/api/v1/auth/logout")
                                .addLogoutHandler(logoutHandler)
                                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
                )
        ;

        return http.build();
    }


}
