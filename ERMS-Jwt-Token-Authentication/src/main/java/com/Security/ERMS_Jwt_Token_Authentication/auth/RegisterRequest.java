package com.Security.ERMS_Jwt_Token_Authentication.auth;


import com.Security.ERMS_Jwt_Token_Authentication.user.Role;

public class RegisterRequest {
    private String firstname;
    private String lastname;
    private String email;
    private String password;
    private Role role;
    private String organizationId;  // Include this for Admin registration
    private String adminId;
    private String managersId;
    private String saleManagerId;


    // Getters and Setters


    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public String getOrganizationId() {
        return organizationId;
    }

    public void setOrganizationId(String organizationId) {
        this.organizationId = organizationId;
    }

    public String getAdminId() {
        return adminId;
    }

    public void setAdminId(String adminId) {
        this.adminId = adminId;
    }

    public String getManagersId() {
        return managersId;
    }

    public void setManagersId(String managersId) {
        this.managersId = managersId;
    }

    public String getSaleManagerId() {
        return saleManagerId;
    }

    public void setSaleManagerId(String saleManagerId) {
        this.saleManagerId = saleManagerId;
    }
}
