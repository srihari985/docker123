package com.Security.ERMS_Jwt_Token_Authentication.saleManager;

import com.Security.ERMS_Jwt_Token_Authentication.managers.Managers;
import com.Security.ERMS_Jwt_Token_Authentication.sales.Sales;
import com.Security.ERMS_Jwt_Token_Authentication.technician.Technician;
import com.Security.ERMS_Jwt_Token_Authentication.user.Role;
import jakarta.persistence.*;

import java.util.List;

@Entity
@Table(name = "_sale_manager", uniqueConstraints = @UniqueConstraint(columnNames = "saleManagerId"))
public class SaleManager {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String firstname;
    private String lastname;
    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;  // e.g., SALE_MANAGER

    @Column(nullable = false, unique = true)
    private String saleManagerId;  // e.g., SMAN-001

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "managers_id", nullable = false)  // Foreign key to Managers
    private Managers manager;

    @OneToMany(mappedBy = "saleManager", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<Sales> sales;

    @OneToMany(mappedBy = "saleManager", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<Technician> technicians;

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

    public String getSaleManagerId() {
        return saleManagerId;
    }

    public void setSaleManagerId(String saleManagerId) {
        this.saleManagerId = saleManagerId;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public Managers getManager() {
        return manager;
    }

    public void setManager(Managers manager) {
        this.manager = manager;
    }

    public List<Sales> getSales() {
        return sales;
    }

    public void setSales(List<Sales> sales) {
        this.sales = sales;
    }

    public List<Technician> getTechnicians() {
        return technicians;
    }

    public void setTechnicians(List<Technician> technicians) {
        this.technicians = technicians;
    }
}