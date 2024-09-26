package com.Security.ERMS_Jwt_Token_Authentication.sales;


import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface SalesRepository extends JpaRepository<Sales, Long> {

    Optional<Sales> findByEmail(String email);

    @Query("SELECT s.saleManagerSalesId FROM Sales s ORDER BY s.saleManagerSalesId DESC")
    List<String> findUserRoleIdByRole(Pageable pageable);


    boolean existsByEmail(String email);
}
