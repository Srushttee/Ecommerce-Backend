package com.shop.ecommerce.service;

import com.shop.ecommerce.exception.OrderException;
import com.shop.ecommerce.model.*;
import com.shop.ecommerce.repository.AddressRepository;
import com.shop.ecommerce.repository.OrderItemRepository;
import com.shop.ecommerce.repository.OrderRepository;
import com.shop.ecommerce.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class OrderServiceImpl implements OrderService {

    private final OrderRepository orderRepository;
    private final CartService cartService;
    private final AddressRepository addressRepository;
    private final UserRepository userRepository;
    private final OrderItemRepository orderItemRepository;

    public OrderServiceImpl(OrderRepository orderRepository,
                            CartService cartService,
                            AddressRepository addressRepository,
                            UserRepository userRepository,
                            OrderItemRepository orderItemRepository) {
        this.orderRepository = orderRepository;
        this.cartService = cartService;
        this.addressRepository = addressRepository;
        this.userRepository = userRepository;
        this.orderItemRepository = orderItemRepository;
    }

    @Override
    public Order createOrder(User user, Address shippAddress) {
        // Ensure shipping address is linked and saved
        shippAddress.setUser(user);
        Address savedAddress = addressRepository.save(shippAddress);
        user.getAddress().add(savedAddress);
        userRepository.save(user);

        // Build order items from current cart
        Cart cart = cartService.findUserCart(user.getId());
        List<OrderItem> orderItems = new ArrayList<>();

        Order order = new Order();
        order.setUser(user);
        order.setShippingAddress(savedAddress);
        order.setOrderDate(LocalDateTime.now());
        order.setCreatedAt(LocalDateTime.now());
        order.setOrderStatus("PENDING");

        // Initialize payment details safely
        PaymentDetails paymentDetails = new PaymentDetails();
        paymentDetails.setStatus("PENDING");
        order.setPaymentDetails(paymentDetails);

        order.setTotalPrice(cart.getTotalPrice());
        order.setTotalItem(cart.getTotalItem());
        order.setDiscount(cart.getDiscount());
        order.setTotalDiscountedPrice(cart.getTotalDiscountedPrice());

        for (CartItem cartItem : cart.getCartitems()) {
            OrderItem orderItem = new OrderItem();
            orderItem.setProduct(cartItem.getProduct());
            orderItem.setQuantity(cartItem.getQuantity());
            orderItem.setSize(cartItem.getSize());
            orderItem.setPrice(cartItem.getPrice());
            orderItem.setDiscountedPrice(cartItem.getDiscountedPrice());
            orderItem.setUserId(cartItem.getUserId());
            orderItem.setOrder(order); // link before saving
            orderItems.add(orderItem);
        }

        order.setOrderItems(orderItems);

        // Save order and items
        Order savedOrder = orderRepository.save(order);
        orderItemRepository.saveAll(orderItems);

        // Clear cart after placing order
//        cartService.clearCart(user.getId());

        return savedOrder;
    }


    @Override
    public Order placedOrder(Long orderId) throws OrderException {
        Order order = findOrderById(orderId);
        order.setOrderStatus("PLACED");
        order.getPaymentDetails().setStatus("COMPLETED");
        return orderRepository.save(order);
    }

    @Override
    public Order confirmedOrder(Long orderId) throws OrderException {
        Order order = findOrderById(orderId);
        order.setOrderStatus("CONFIRMED");
        return orderRepository.save(order);
    }

    @Override
    public Order shippedOrder(Long orderId) throws OrderException {
        Order order = findOrderById(orderId);
        order.setOrderStatus("SHIPPED");
        return orderRepository.save(order);
    }

    @Override
    public Order deliveredOrder(Long orderId) throws OrderException {
        Order order = findOrderById(orderId);
        order.setOrderStatus("DELIVERED");
        return orderRepository.save(order);
    }

    @Override
    public Order cancelOrder(Long orderId) throws OrderException {
        Order order = findOrderById(orderId);
        order.setOrderStatus("CANCELED");
        return orderRepository.save(order);
    }

    @Override
    public Order findOrderById(Long orderId) throws OrderException {
        return orderRepository.findById(orderId).orElseThrow(
                () -> new OrderException("Order not found with id " + orderId));
    }

    @Override
    public List<Order> usersOrderHistory(Long userId) {
        return orderRepository.getUsersOrders(userId);
    }

    @Override
    public List<Order> getAllOrders() {
        return orderRepository.findAll();
    }

    @Override
    public void deleteOrder(Long orderId) throws OrderException {
        Order order = findOrderById(orderId);
        orderRepository.delete(order);
    }

    // Add this method to your implementation class
    @Override
    public Order updateShippingAddress(Long orderId, Address newAddress) throws OrderException {
        Order order = findOrderById(orderId);

        if (order.getShippingAddress() != null && order.getShippingAddress().getId() > 0) {
            // Update the existing address
            Address existingAddress = order.getShippingAddress();
            existingAddress.setFirstName(newAddress.getFirstName());
            existingAddress.setLastName(newAddress.getLastName());
            existingAddress.setStreetAddress(newAddress.getStreetAddress());
            existingAddress.setCity(newAddress.getCity());
            existingAddress.setState(newAddress.getState());
            existingAddress.setZipCode(newAddress.getZipCode());
            existingAddress.setMobile(newAddress.getMobile());

            addressRepository.save(existingAddress);
            return orderRepository.save(order);
        } else {
            // If no address exists, create and link a new one
            newAddress.setUser(order.getUser());
            Address savedNewAddress = addressRepository.save(newAddress);
            order.setShippingAddress(savedNewAddress);
            return orderRepository.save(order);
        }
    }
}
