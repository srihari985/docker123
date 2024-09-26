package com.Security.ERMS_Jwt_Token_Authentication.saleManager;


import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface SaleManagerRepository extends JpaRepository<SaleManager, Long> {

    Optional<SaleManager> findByEmail(String email);

    @Query("SELECT s.saleManagerId FROM SaleManager s ORDER BY s.saleManagerId DESC")
    List<String> findUserRoleIdByRole(Pageable pageable);

    // Find SaleManager by their unique saleManagerId
    Optional<SaleManager> findBySaleManagerId(String saleManagerId);


    boolean existsByEmail(String email);
}
