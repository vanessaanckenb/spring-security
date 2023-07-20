package br.com.vanessaancken.springsecurity.repository;

import br.com.vanessaancken.springsecurity.domain.product.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ProductRepository extends JpaRepository<Product, String> {
}
