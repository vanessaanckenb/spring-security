package br.com.vanessaancken.springsecurity.service.product;

import br.com.vanessaancken.springsecurity.repository.ProductRepository;
import lombok.AllArgsConstructor;
import org.springframework.data.annotation.Transient;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class DeleteProductService {

    private final ProductRepository repository;

    @Transient
    public void execute(String id){
        repository.deleteById(id);
    }
}
