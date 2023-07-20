package br.com.vanessaancken.springsecurity.domain.user.resources;

import jakarta.validation.constraints.NotBlank;

public record UserDTO(@NotBlank String login, @NotBlank String password) {
}
