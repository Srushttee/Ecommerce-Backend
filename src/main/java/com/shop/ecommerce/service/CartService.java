package com.shop.ecommerce.service;

import com.shop.ecommerce.exception.ProductException;
import com.shop.ecommerce.model.Cart;
import com.shop.ecommerce.model.User;
import com.shop.ecommerce.request.AddItemRequest;
import org.springframework.stereotype.Service;

@Service
public interface CartService {
    Cart createCart(User user);

    String addCartItem(Long userId, AddItemRequest req) throws ProductException;

    Cart findUserCart(Long userId);
}
