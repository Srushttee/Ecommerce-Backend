package com.shop.ecommerce.controller;

import com.shop.ecommerce.exception.OrderException;
import com.shop.ecommerce.exception.UserException;
import com.shop.ecommerce.model.Address;
import com.shop.ecommerce.model.Order;
import com.shop.ecommerce.model.User;
import com.shop.ecommerce.service.OrderService;
import com.shop.ecommerce.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/orders")
public class OrderController {
    @Autowired
    private OrderService orderService;

    @Autowired
    private UserService userService;

    @PostMapping("/")
    public ResponseEntity<Order> createOrder(@RequestBody Address shippingAddress,
                                             @RequestHeader("Authorization") String authHeader) throws UserException {
        String jwt = extractJwtFromHeader(authHeader);
        User user = userService.findUserProfileByJwt(jwt);
        Order order = orderService.createOrder(user, shippingAddress);
        System.out.println("Order : " + order);
        return new ResponseEntity<>(order, HttpStatus.CREATED);
    }

    @GetMapping("/user")
    public ResponseEntity<List<Order>> usersOrdersHistory(@RequestHeader("Authorization") String authHeader) throws UserException {
        String jwt = extractJwtFromHeader(authHeader);
        User user = userService.findUserProfileByJwt(jwt);
        List<Order> orders = orderService.usersOrderHistory(user.getId());
        return new ResponseEntity<>(orders, HttpStatus.CREATED);
    }

    @GetMapping("/{Id}")
    public ResponseEntity<Order> findOrderById(@PathVariable("Id") Long orderId,
                                               @RequestHeader("Authorization") String authHeader) throws UserException, OrderException {
        String jwt = extractJwtFromHeader(authHeader);
        User user = userService.findUserProfileByJwt(jwt);
        Order order = orderService.findOrderById(orderId);
        return new ResponseEntity<>(order, HttpStatus.ACCEPTED);
    }

    // Helper method to parse raw JWT token
    private String extractJwtFromHeader(String authHeader) throws UserException {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new UserException("Missing or invalid Authorization header");
        }
        return authHeader.substring(7); // Remove "Bearer " prefix
    }

    @PutMapping("/{orderId}/shippingAddress")
    public ResponseEntity<Order> updateShippingAddress(@PathVariable Long orderId,
                                                       @RequestBody Address newAddress,
                                                       @RequestHeader("Authorization") String authHeader) throws OrderException, UserException {
        // Optional: Add logic to verify user ownership of the order for security
        String jwt = extractJwtFromHeader(authHeader);
        User user = userService.findUserProfileByJwt(jwt);

        Order updatedOrder = orderService.updateShippingAddress(orderId, newAddress);

        return new ResponseEntity<>(updatedOrder, HttpStatus.OK);
    }
}
