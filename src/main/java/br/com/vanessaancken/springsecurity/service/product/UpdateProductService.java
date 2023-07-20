package br.com.vanessaancken.springsecurity.service.product;

import br.com.vanessaancken.springsecurity.domain.product.ProductResponseDTO;
import br.com.vanessaancken.springsecurity.domain.product.ProductToUpdateRequestDTO;
import br.com.vanessaancken.springsecurity.repository.ProductRepository;
import br.com.vanessaancken.springsecurity.service.product.converters.ProductToProductResponseDTOConverter;
import lombok.AllArgsConstructor;
import org.springframework.data.annotation.Transient;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class UpdateProductService {

    private final ProductToProductResponseDTOConverter productToProductResponseDTOConverter;
    private final ProductRepository repository;

    @Transient
    public ProductResponseDTO execute(ProductToUpdateRequestDTO productDTO){
        final var product = repository.getReferenceById(productDTO.id());
        product.updateProduct(productDTO);
        return productToProductResponseDTOConverter.convert(product);
    }
}
