package br.com.vanessaancken.springsecurity.configs.exceptions;

import jakarta.persistence.EntityNotFoundException;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionsHandler {

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity notFoundHandler() {
        return ResponseEntity.notFound().build();
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity validationErrorHandler(MethodArgumentNotValidException exception) {
        return ResponseEntity.badRequest().body(exception.getFieldErrors().stream().map(ValidationErrorDTO::new).toList());
    }

    private record ValidationErrorDTO(String field, String message) {
        public ValidationErrorDTO(FieldError erro) {
            this(erro.getField(), erro.getDefaultMessage());
        }
    }
}