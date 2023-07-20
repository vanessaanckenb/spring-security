package br.com.vanessaancken.springsecurity.domain.product;

import jakarta.validation.constraints.NotBlank;

import java.math.BigDecimal;

public record ProductToUpdateRequestDTO(@NotBlank String id, String name, BigDecimal price) {
}
