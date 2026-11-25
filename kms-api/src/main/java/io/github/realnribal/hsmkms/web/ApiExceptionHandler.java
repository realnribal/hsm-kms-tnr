package io.github.realnribal.hsmkms.web;

import io.github.realnribal.hsmkms.hsm.KmsException;
import io.github.realnribal.hsmkms.web.dto.ApiModels.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(KmsException.class)
    public ResponseEntity<ErrorResponse> kms(KmsException ex) {
        log.warn("request failed code={} ckR={}", ex.code(), ex.ckR());
        return error(ex.status(), ex.code(), ex.getMessage(), ex.ckR());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> invalid(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(err -> err.getField() + " is invalid")
                .collect(Collectors.joining("; "));
        if (message.isBlank()) {
            message = "Request is invalid";
        }
        log.warn("validation failed");
        return error(400, "VALIDATION", message, null);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> unreadable(HttpMessageNotReadableException ex) {
        log.warn("malformed json");
        return error(400, "VALIDATION", "Malformed JSON request", null);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> unexpected(Exception ex) {
        log.error("unhandled type={}", ex.getClass().getSimpleName(), ex);
        return error(500, "INTERNAL", "Internal error", null);
    }

    private static ResponseEntity<ErrorResponse> error(int status, String code, String message, String ckR) {
        return ResponseEntity.status(status).body(new ErrorResponse(code, message, MDC.get("traceId"), ckR));
    }
}
