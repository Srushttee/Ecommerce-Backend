package com.shop.ecommerce.repository;

import com.shop.ecommerce.model.Category;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CategoryRepository extends JpaRepository<Category, Long> {

    // Find by name only (may cause conflicts if used alone)
    Category findByName(String name);

    // Find category by name + parent (ensures proper hierarchy)
    Optional<Category> findByNameAndParentCategory(String name, Category parentCategory);

    // Find category by name + level (cleaner and avoids wrong reuse)
    Optional<Category> findByNameAndLevel(String name, int level);
}
