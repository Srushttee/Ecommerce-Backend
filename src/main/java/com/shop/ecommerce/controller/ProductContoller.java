package com.shop.ecommerce.controller;

import com.shop.ecommerce.exception.ProductException;
import com.shop.ecommerce.model.Product;
import com.shop.ecommerce.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class ProductContoller {
    @Autowired
    private ProductService productService;

    @GetMapping("/products")
    public ResponseEntity<Page<Product>> findProductsByCategoryHandler(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) List<String> color,
            @RequestParam(required = false) List<String> size,
            @RequestParam(required = false, defaultValue = "0") Integer minPrice,
            @RequestParam(required = false, defaultValue = "1000000") Integer maxPrice,
            @RequestParam(required = false, defaultValue = "0") Integer minDiscount,
            @RequestParam(required = false, defaultValue = "price") String sort,
            @RequestParam(required = false) String stock, // optional, handle null accordingly
            @RequestParam(required = false, defaultValue = "0") Integer pageNumber,
            @RequestParam(required = false, defaultValue = "10") Integer pageSize) {

        Page<Product> res = productService.getAllProducts(category, color, size, minPrice, maxPrice, minDiscount,
                sort, stock, pageNumber, pageSize);
        System.out.println("Complete Products");
        return new ResponseEntity<>(res, HttpStatus.ACCEPTED);
    }

    @GetMapping("/products/id/{productId}")
    public ResponseEntity<Product> findProductByHandler(@PathVariable Long productId) throws ProductException {
        Product product = productService.findByProductId(productId);
        return new ResponseEntity<>(product, HttpStatus.ACCEPTED);
    }
}
