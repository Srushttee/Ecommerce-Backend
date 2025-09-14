package com.shop.ecommerce.service;

import com.shop.ecommerce.exception.ProductException;
import com.shop.ecommerce.model.Product;
import com.shop.ecommerce.request.CreateProductRequest;
import org.springframework.data.domain.Page;

import java.util.List;

public interface ProductService {
    Product createProduct(CreateProductRequest req);

    String deleteProduct(Long productId) throws ProductException;

    Product updateProduct(Long productId, Product product) throws ProductException;

    Product findByProductId(Long id) throws ProductException;

    List<Product> findByProductByCategory(String category);

    Page<Product> getAllProducts(String category, List<String> colors, List<String> sizes, Integer minPrice, Integer maxPrice, Integer minDiscount, String sort, String stock, Integer pageNumber, Integer pageSize);

    List<Product> findAllProducts();
}
