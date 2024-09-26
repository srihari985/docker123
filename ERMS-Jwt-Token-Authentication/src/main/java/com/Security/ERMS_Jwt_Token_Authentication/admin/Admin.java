package com.Security.ERMS_Jwt_Token_Authentication.admin;

import com.Security.ERMS_Jwt_Token_Authentication.Orgnization.Organization;
import com.Security.ERMS_Jwt_Token_Authentication.managers.Managers;
import com.Security.ERMS_Jwt_Token_Authentication.user.Role;
import jakarta.persistence.*;

import java.util.List;

@Entity
public class Admin {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    private String adminId;

    @ManyToOne
    @JoinColumn(name = "organization_id")
    private Organization organization;

    @OneToMany(mappedBy = "admin", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Managers> managers;

    // Getters and Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

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

    public String getAdminId() {
        return adminId;
    }

    public void setAdminId(String adminId) {
        this.adminId = adminId;
    }

    public Organization getOrganization() {
        return organization;
    }

    public void setOrganization(Organization organization) {
        this.organization = organization;
    }

    public List<Managers> getManagers() {
        return managers;
    }

    public void setManagers(List<Managers> managers) {
        this.managers = managers;
    }
}
