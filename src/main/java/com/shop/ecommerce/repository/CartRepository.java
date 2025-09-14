package com.shop.ecommerce.repository;

import com.shop.ecommerce.model.Cart;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CartRepository extends JpaRepository<Cart, Long> {
    @Query("SELECT c From Cart c Where c.user.id = :userId")
    Cart findByUserId(@Param("userId") Long userId);
}
