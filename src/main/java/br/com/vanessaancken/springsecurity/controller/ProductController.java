package br.com.vanessaancken.springsecurity.controller;

import br.com.vanessaancken.springsecurity.domain.product.ProductRequestDTO;
import br.com.vanessaancken.springsecurity.domain.product.ProductResponseDTO;
import br.com.vanessaancken.springsecurity.domain.product.ProductToUpdateRequestDTO;
import br.com.vanessaancken.springsecurity.service.product.*;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

@AllArgsConstructor
@RestController
@RequestMapping("/products")
public class ProductController {

    private final SaveProductService saveProductService;
    private final GetProductByIdService getProductByIdService;
    private final GetProductsService getProductsService;
    private final UpdateProductService updateProductService;
    private final DeleteProductService deleteProductService;

    @PostMapping
    @Transactional
    public ResponseEntity saveProduct(@RequestBody @Valid ProductRequestDTO productRequest, UriComponentsBuilder uriComponentsBuilder) {
        final var productResponse = saveProductService.execute(productRequest);
        final var uri = uriComponentsBuilder
                .path("/products/{id}")
                .buildAndExpand(productResponse.id())
                .toUri();
        return ResponseEntity
                .created(uri)
                .body(productResponse);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ProductResponseDTO> getProductById(@PathVariable String id) {
        final var productResponse = getProductByIdService.execute(id);
        return ResponseEntity.ok(productResponse);
    }
    @GetMapping
    public ResponseEntity<Page<ProductResponseDTO>> getProducts(@PageableDefault(size = 10, sort = {"name"}) Pageable pages) {
        final var productsResponsePages = getProductsService.execute(pages);
        return ResponseEntity.ok(productsResponsePages);
    }

    @PutMapping
    @Transactional
    public ResponseEntity atualizar(@RequestBody @Valid ProductToUpdateRequestDTO productRequest) {
        var productResponse = updateProductService.execute(productRequest);
        return ResponseEntity.ok(productResponse);
    }

    @DeleteMapping("/{id}")
    @Transactional
    public ResponseEntity excluir(@PathVariable String id) {
        deleteProductService.execute(id);
        return ResponseEntity.noContent().build();
    }
}
