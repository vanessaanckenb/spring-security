package br.com.vanessaancken.springsecurity.service.product;

import br.com.vanessaancken.springsecurity.domain.product.ProductRequestDTO;
import br.com.vanessaancken.springsecurity.domain.product.ProductResponseDTO;
import br.com.vanessaancken.springsecurity.repository.ProductRepository;
import br.com.vanessaancken.springsecurity.service.product.converters.ProductRequestDTOToProductConverter;
import br.com.vanessaancken.springsecurity.service.product.converters.ProductToProductResponseDTOConverter;
import lombok.AllArgsConstructor;
import org.springframework.data.annotation.Transient;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class SaveProductService {

    private final ProductRequestDTOToProductConverter productRequestDTOToProductConverter;
    private final ProductToProductResponseDTOConverter productToProductResponseDTOConverter;
    private final ProductRepository repository;

    @Transient
    public ProductResponseDTO execute(ProductRequestDTO productDTO){
        var product = productRequestDTOToProductConverter.convert(productDTO);
        repository.save(product);
        return productToProductResponseDTOConverter.convert(product);
    }
}
