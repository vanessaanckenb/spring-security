package br.com.vanessaancken.springsecurity.service.product;

import br.com.vanessaancken.springsecurity.domain.product.ProductResponseDTO;
import br.com.vanessaancken.springsecurity.repository.ProductRepository;
import br.com.vanessaancken.springsecurity.service.product.converters.ProductToProductResponseDTOConverter;
import lombok.AllArgsConstructor;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class GetProductsService {

    private final ProductToProductResponseDTOConverter productToProductResponseDTOConverter;
    private final ProductRepository repository;

    @Transient
    public Page<ProductResponseDTO> execute(Pageable pages){
        return repository
                .findAll(pages)
                .map(protuct -> productToProductResponseDTOConverter.convert(protuct));
    }
}
