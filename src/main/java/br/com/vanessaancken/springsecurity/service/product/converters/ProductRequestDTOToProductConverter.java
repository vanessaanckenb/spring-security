package br.com.vanessaancken.springsecurity.service.product.converters;

import br.com.vanessaancken.springsecurity.domain.product.Product;
import br.com.vanessaancken.springsecurity.domain.product.ProductRequestDTO;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class ProductRequestDTOToProductConverter {

    public Product convert(ProductRequestDTO productDTO){
        return Product
                .builder()
                .name(productDTO.name())
                .price(productDTO.price())
                .build();
    }
}
