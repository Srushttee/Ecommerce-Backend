package com.shop.ecommerce.controller;

import com.shop.ecommerce.exception.CartItemException;
import com.shop.ecommerce.exception.UserException;
import com.shop.ecommerce.model.CartItem;
import com.shop.ecommerce.model.User;
import com.shop.ecommerce.response.ApiResponse;
import com.shop.ecommerce.service.CartItemService;
import com.shop.ecommerce.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/cart_items")
public class CartItemController {

    @Autowired
    private CartItemService cartItemService;

    @Autowired
    private UserService userService;

    @DeleteMapping("/{cartItemId}")
//    @Operation(description = "Remove Cart Item From Cart")
//    @SwaggerApiResponse(description = "Delete Item")
    public ResponseEntity<ApiResponse> deleteCartItem(
            @PathVariable Long cartItemId,
            @RequestHeader("Authorization") String authHeader
    ) throws UserException, CartItemException {
        String jwt = getRawToken(authHeader);
        User user = userService.findUserProfileByJwt(jwt);
        cartItemService.removeCartItem(user.getId(), cartItemId);

        ApiResponse res = new ApiResponse();
        res.setMessage("item removed from cart");
        res.setStatus(true);
        return new ResponseEntity<>(res, HttpStatus.OK);
    }

    @PutMapping("/{cartItemId}")
//    @Operation(description = "Update Item To Cart")
    public ResponseEntity<CartItem> updateCartItem(
            @RequestBody CartItem cartItem,
            @PathVariable Long cartItemId,
            @RequestHeader("Authorization") String authHeader
    ) throws UserException, CartItemException {
        String jwt = getRawToken(authHeader);
        User user = userService.findUserProfileByJwt(jwt);
        CartItem updatedCartItem = cartItemService.updateCartItem(user.getId(), cartItemId, cartItem);

        return new ResponseEntity<>(updatedCartItem, HttpStatus.OK);
    }

    // Helper: extract the raw token from the Authorization header
    private String getRawToken(String authHeader) throws UserException {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new UserException("Missing or invalid Authorization header");
        }
        return authHeader.substring(7);
    }
}
