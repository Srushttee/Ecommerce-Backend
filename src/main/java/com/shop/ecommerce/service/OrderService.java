package com.shop.ecommerce.service;

import com.shop.ecommerce.exception.OrderException;
import com.shop.ecommerce.model.Address;
import com.shop.ecommerce.model.Order;
import com.shop.ecommerce.model.User;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface OrderService {
    Order createOrder(User user, Address shippingAddress);

    Order findOrderById(Long orderId) throws OrderException;

    List<Order> usersOrderHistory(Long userId);

    Order placedOrder(Long orderId) throws OrderException;

    Order confirmedOrder(Long orderId) throws OrderException;

    Order shippedOrder(Long orderId) throws OrderException;

    Order deliveredOrder(Long orderId) throws OrderException;

    List<Order> getAllOrders();

    Order cancelOrder(Long orderId) throws OrderException;

    void deleteOrder(Long orderId) throws OrderException;

    Order updateShippingAddress(Long orderId, Address newAddress) throws OrderException;
}
