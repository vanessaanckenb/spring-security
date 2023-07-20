package br.com.vanessaancken.springsecurity.service.product;

import br.com.vanessaancken.springsecurity.domain.product.ProductResponseDTO;
import br.com.vanessaancken.springsecurity.repository.ProductRepository;
import br.com.vanessaancken.springsecurity.service.product.converters.ProductToProductResponseDTOConverter;
import lombok.AllArgsConstructor;
import org.springframework.data.annotation.Transient;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class GetProductByIdService {

    private final ProductToProductResponseDTOConverter productToProductResponseDTOConverter;
    private final ProductRepository repository;

    @Transient
    public ProductResponseDTO execute(String id){
        final var product = repository.getReferenceById(id);
        return productToProductResponseDTOConverter.convert(product);
    }
}
