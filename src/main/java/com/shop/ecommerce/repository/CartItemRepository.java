package com.shop.ecommerce.repository;

import com.shop.ecommerce.model.Cart;
import com.shop.ecommerce.model.CartItem;
import com.shop.ecommerce.model.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CartItemRepository extends JpaRepository<CartItem, Long> {

    @Query("Select ci from CartItem ci Where ci.cart =:cart And ci.product =:product And ci.size = :size And ci.userId=:userId")
    CartItem isCartItemExist(@Param("cart") Cart cart, @Param("product") Product product, @Param("size") String size, @Param("userId") Long userId);

    Long cart(Cart cart);
}
