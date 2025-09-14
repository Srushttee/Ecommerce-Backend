package com.shop.ecommerce.controller;

import com.shop.ecommerce.exception.ProductException;
import com.shop.ecommerce.exception.UserException;
import com.shop.ecommerce.model.Cart;
import com.shop.ecommerce.model.User;
import com.shop.ecommerce.request.AddItemRequest;
import com.shop.ecommerce.response.ApiResponse;
import com.shop.ecommerce.service.CartService;
import com.shop.ecommerce.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/cart")
public class CartController {
    @Autowired
    private CartService cartService;

    @Autowired
    private UserService userService;

    @GetMapping("/")
    public ResponseEntity<Cart> findUserCart(@RequestHeader("Authorization") String authHeader) throws UserException {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new UserException("Missing or invalid Authorization header");
        }
        String jwt = authHeader.substring(7); // Remove "Bearer " prefix
        User user = userService.findUserProfileByJwt(jwt);
        Cart cart = cartService.findUserCart(user.getId());
        return new ResponseEntity<>(cart, HttpStatus.OK);
    }

    @PutMapping("/add")
    public ResponseEntity<ApiResponse> addItemToCart(@RequestBody AddItemRequest req,
                                                     @RequestHeader("Authorization") String authHeader)
            throws UserException, ProductException {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new UserException("Missing or invalid Authorization header");
        }
        String jwt = authHeader.substring(7); // Remove "Bearer " prefix
        User user = userService.findUserProfileByJwt(jwt);
        cartService.addCartItem(user.getId(), req);

        ApiResponse res = new ApiResponse();
        res.setMessage("Item added to cart");
        res.setStatus(true);
        return new ResponseEntity<>(res, HttpStatus.OK);
    }
}
