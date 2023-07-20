package br.com.vanessaancken.springsecurity.domain.product;

import lombok.Builder;

import java.math.BigDecimal;

@Builder
public record ProductResponseDTO(String id, String name, BigDecimal price) {
}
