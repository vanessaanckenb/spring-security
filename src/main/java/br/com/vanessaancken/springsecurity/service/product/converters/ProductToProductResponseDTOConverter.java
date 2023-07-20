package br.com.vanessaancken.springsecurity.service.product.converters;

import br.com.vanessaancken.springsecurity.domain.product.Product;
import br.com.vanessaancken.springsecurity.domain.product.ProductResponseDTO;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class ProductToProductResponseDTOConverter {

    public ProductResponseDTO convert(Product product){
        return ProductResponseDTO
                .builder()
                .id(product.getId())
                .name(product.getName())
                .price(product.getPrice())
                .build();
    }
}
