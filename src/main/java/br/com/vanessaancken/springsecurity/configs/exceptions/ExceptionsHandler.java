package br.com.vanessaancken.springsecurity.configs.exceptions;

import jakarta.persistence.EntityNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.naming.AuthenticationException;
import java.nio.file.AccessDeniedException;

@RestControllerAdvice
public class ExceptionsHandler {

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity handleEntityNotFoundException(){
        return ResponseEntity.notFound().build();
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity handleMethodArgumentNotValidException(MethodArgumentNotValidException exception) {
        var erros = exception
                .getFieldErrors()
                .stream()
                .map(ValidationErrorDTO::new)
                .toList();
        return ResponseEntity.badRequest().body(erros);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity handleStatus400(HttpMessageNotReadableException exception) {
        return ResponseEntity.badRequest().body(exception.getMessage());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity handleBadCredentials() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new AuthenticationErrorDTO("Invalid credentials."));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity handleAuhtenticationError() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new AuthenticationErrorDTO("Authentication failed."));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity handleAcessDenied() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new AuthenticationErrorDTO("Access denied."));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity handleStatus500(Exception exception) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new AuthenticationErrorDTO(exception.getLocalizedMessage()));
    }

    private record ValidationErrorDTO(String field, String message) {
        public ValidationErrorDTO(FieldError erro) {
            this(erro.getField(), erro.getDefaultMessage());
        }
    }

    private record AuthenticationErrorDTO(String error) {
    }
}
