package com.shop.ecommerce.controller;

import com.razorpay.Payment;
import com.razorpay.PaymentLink;
import com.razorpay.RazorpayClient;
import com.razorpay.RazorpayException;
import com.shop.ecommerce.exception.OrderException;
import com.shop.ecommerce.model.Order;
import com.shop.ecommerce.repository.OrderRepository;
import com.shop.ecommerce.response.ApiResponse;
import com.shop.ecommerce.response.PaymentLinkResponse;
import com.shop.ecommerce.service.OrderService;
import com.shop.ecommerce.service.UserService;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class PaymentController {
    @Value("${razorpay.api.key}")
    String apiKey;

    @Value("${razorpay.api.secret}")
    String apiSecret;

    @Autowired
    private OrderService orderService;

    @Autowired
    private UserService userService;
    @Autowired
    private OrderRepository orderRepository;

    @Value("${frontend.base.url}")
    private String frontendBaseUrl;

    @PostMapping("/payments/{orderId}")
    public ResponseEntity<PaymentLinkResponse> createPaymentLink(@PathVariable Long orderId,
                                                                 @RequestHeader("Authorization") String jwt) throws OrderException, RazorpayException {
        Order order = orderService.findOrderById(orderId);
        try {
            RazorpayClient razorpayClient = new RazorpayClient(apiKey, apiSecret);
            JSONObject paymentLinkRequest = new JSONObject();
            paymentLinkRequest.put("amount", order.getTotalPrice() * 100);
            paymentLinkRequest.put("currency", "INR");

            JSONObject customer = new JSONObject();
            customer.put("name", order.getUser().getFirstName());
            customer.put("email", order.getUser().getEmail());
            paymentLinkRequest.put("customer", customer);

            JSONObject notify = new JSONObject();
            notify.put("sms", true);
            notify.put("email", true);
            paymentLinkRequest.put("notify", notify);

            paymentLinkRequest.put("callback_url", frontendBaseUrl + "/payment/" + orderId);
            paymentLinkRequest.put("callback_method", "get");

            PaymentLink payment = razorpayClient.paymentLink.create(paymentLinkRequest);

            String paymentLinkId = payment.get("id");
            String paymentLinkUrl = payment.get("short_url");

            PaymentLinkResponse res = new PaymentLinkResponse();
            res.setPayment_link_url(paymentLinkUrl);
            res.setPayment_link_id(paymentLinkId);

            return new ResponseEntity<PaymentLinkResponse>(res, HttpStatus.CREATED);
        } catch (Exception e) {
            throw new RazorpayException(e.getMessage());
        }

    }

    @GetMapping("/payments")
    public ResponseEntity<ApiResponse> redirect(@RequestParam(name = "payment_id") String paymentId,
                                                @RequestParam(name = "order_id") Long orderId) throws OrderException, RazorpayException {
        Order order = orderService.findOrderById(orderId);
        RazorpayClient razorpayClient = new RazorpayClient(apiKey, apiSecret);
        try {
            Payment payment = razorpayClient.payments.fetch(paymentId);
            if (payment.get("status").equals("captured")) {
                order.getPaymentDetails().setPaymentId(paymentId);
                order.getPaymentDetails().setStatus("COMPLETED");
                order.setOrderStatus("PLACED");
                orderRepository.save(order);
            }
            ApiResponse apiResponse = new ApiResponse();
            apiResponse.setStatus(true);
            apiResponse.setMessage("Your order get placed");
            return new ResponseEntity<ApiResponse>(apiResponse, HttpStatus.ACCEPTED);
        } catch (Exception e) {
            throw new RazorpayException(e.getMessage());
        }
    }
}
