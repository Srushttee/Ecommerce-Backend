package com.shop.ecommerce.service;

import com.shop.ecommerce.exception.CartItemException;
import com.shop.ecommerce.exception.UserException;
import com.shop.ecommerce.model.Cart;
import com.shop.ecommerce.model.CartItem;
import com.shop.ecommerce.model.Product;
import org.springframework.stereotype.Service;

@Service
public interface CartItemService {
    CartItem createCartItem(CartItem cartItem);

    CartItem updateCartItem(Long userId, Long id, CartItem cartItem) throws CartItemException, UserException;

    CartItem isCartItemExist(Cart cart, Product product, String size, Long userId);

    void removeCartItem(Long userId, Long cartItemId) throws CartItemException, UserException;

    CartItem findCartItemById(Long cartItemId) throws CartItemException;
}
