package br.com.vanessaancken.springsecurity.domain.product;

import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;

@Table(name = "products")
@Entity(name = "Product")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;
    private String name;
    private BigDecimal price;

    public void updateProduct(ProductToUpdateRequestDTO productDTO){
        if(productDTO.name() != null){
            this.name = productDTO.name();
        }
        if(productDTO.price() != null){
            this.price = productDTO.price();
        }
    }
}
