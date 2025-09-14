package com.shop.ecommerce.service;

import com.shop.ecommerce.exception.ProductException;
import com.shop.ecommerce.model.Category;
import com.shop.ecommerce.model.Product;
import com.shop.ecommerce.repository.CategoryRepository;
import com.shop.ecommerce.repository.ProductRepository;
import com.shop.ecommerce.request.CreateProductRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class ProductServiceImpl implements ProductService {
    private final ProductRepository productRepository;

    private final UserService userService;

    private final CategoryRepository categoryRepository;

    public ProductServiceImpl(ProductRepository productRepository, UserService userService, CategoryRepository categoryRepository) {
        this.productRepository = productRepository;
        this.userService = userService;
        this.categoryRepository = categoryRepository;
    }

    @Override
    public Product createProduct(CreateProductRequest req) {
        Category topLevel;
        Category secondLevel;
        Category thirdLevel = null;

        // Handle Top Level Category
        if (req.getTopLevelCategory() != null && !req.getTopLevelCategory().isBlank()) {
            topLevel = categoryRepository.findByNameAndLevel(req.getTopLevelCategory(), 1)
                    .orElseGet(() -> {
                        Category newCat = new Category();
                        newCat.setName(req.getTopLevelCategory());
                        newCat.setLevel(1);
                        return categoryRepository.save(newCat);
                    });
        } else {
            topLevel = null;
        }

        // Handle Second Level Category
        if (req.getSecondLevelCategory() != null && !req.getSecondLevelCategory().isBlank()) {
            secondLevel = categoryRepository.findByNameAndParentCategory(req.getSecondLevelCategory(), topLevel)
                    .orElseGet(() -> {
                        Category newCat = new Category();
                        newCat.setName(req.getSecondLevelCategory());
                        newCat.setLevel(2);
                        newCat.setParentCategory(topLevel);
                        return categoryRepository.save(newCat);
                    });
        } else {
            secondLevel = null;
        }

        // Handle Third Level Category
        if (req.getThirdLevelCategory() != null && !req.getThirdLevelCategory().isBlank()) {
            thirdLevel = categoryRepository.findByNameAndParentCategory(req.getThirdLevelCategory(), secondLevel)
                    .orElseGet(() -> {
                        Category newCat = new Category();
                        newCat.setName(req.getThirdLevelCategory());
                        newCat.setLevel(3);
                        newCat.setParentCategory(secondLevel);
                        return categoryRepository.save(newCat);
                    });
        }

        // Create Product
        Product product = new Product();
        product.setTitle(req.getTitle());
        product.setColor(req.getColor());
        product.setDescription(req.getDescription());
        product.setDiscountedPrice((double) req.getDiscountedPrice());
        product.setDiscountPercent(req.getDiscountPercent());
        product.setImageUrl(req.getImageUrl());
        product.setBrand(req.getBrand());
        product.setPrice(req.getPrice());
        product.setSizes(req.getSize());
        product.setQuantity(req.getQuantity());

        // Set the deepest available category
        if (thirdLevel != null) {
            product.setCategory(thirdLevel);
        } else if (secondLevel != null) {
            product.setCategory(secondLevel);
        } else if (topLevel != null) {
            product.setCategory(topLevel);
        }

        product.setCreatedAt(LocalDateTime.now());
        return productRepository.save(product);
    }


    @Override
    public String deleteProduct(Long productId) throws ProductException {
        Product product = findByProductId(productId);
        product.getSizes().clear();
        productRepository.delete(product);
        return "Product Deleted Successfully";
    }

    @Override
    public Product updateProduct(Long productId, Product req) throws ProductException {
        Product product = findByProductId(productId);
        if (req.getQuantity() != 0) {
            product.setQuantity(req.getQuantity());
        }
        return productRepository.save(product);
    }

    @Override
    public Product findByProductId(Long id) throws ProductException {
        Optional<Product> opt = productRepository.findById(id);
        if (opt.isPresent()) {
            return opt.get();
        }
        throw new ProductException("Product not found with id - " + id);
    }

    @Override
    public List<Product> findByProductByCategory(String category) {
        return List.of();
    }

    @Override
    public Page<Product> getAllProducts(String category, List<String> colors, List<String> sizes, Integer minPrice, Integer maxPrice, Integer minDiscount, String sort, String stock, Integer pageNumber, Integer pageSize) {
        Pageable pageable = PageRequest.of(pageNumber, pageSize);

        // Initialize lists if null
        if (colors == null) {
            colors = new ArrayList<>();
        }
        if (sizes == null) {
            sizes = new ArrayList<>();
        }

        // Start with filtered products by category and price
        List<Product> products = productRepository.filterProducts(category, minPrice, maxPrice, minDiscount, sort);

        // Filter by colors if present
        List<Product> filteredProducts = new ArrayList<>();
        if (!colors.isEmpty()) {
            for (Product p : products) {
                for (String color : colors) {
                    if (color.equalsIgnoreCase(p.getColor())) {
                        filteredProducts.add(p);
                        break;
                    }
                }
            }
        } else {
            filteredProducts = new ArrayList<>(products);
        }

        // Filter by sizes if present
        List<Product> sizeFiltered = new ArrayList<>();
        if (!sizes.isEmpty()) {
            for (Product p : filteredProducts) {
                for (String size : sizes) {
                    if (p.getSizes().contains(size)) {
                        sizeFiltered.add(p);
                        break;
                    }
                }
            }
        } else {
            sizeFiltered = filteredProducts;
        }

        // Filter by stock status
        List<Product> stockFiltered = new ArrayList<>();
        if (stock != null) {
            if (stock.equals("in_stock")) {
                for (Product p : sizeFiltered) {
                    if (p.getQuantity() > 0) {
                        stockFiltered.add(p);
                    }
                }
            } else if (stock.equals("out_of_stock")) {
                for (Product p : sizeFiltered) {
                    if (p.getQuantity() < 1) {
                        stockFiltered.add(p);
                    }
                }
            } else {
                stockFiltered = sizeFiltered;
            }
        } else {
            stockFiltered = sizeFiltered;
        }

        int startIndex = Math.toIntExact(pageable.getOffset());
        int endIndex = Math.min(startIndex + pageable.getPageSize(), stockFiltered.size());

        List<Product> pageContent = new ArrayList<>();
        if (startIndex <= endIndex) {
            pageContent = stockFiltered.subList(startIndex, endIndex);
        }

        Page<Product> filteredPage = new PageImpl<>(pageContent, pageable, stockFiltered.size());

        return filteredPage;
    }

    @Override
    public List<Product> findAllProducts() {
        return productRepository.findAll();
    }
}
