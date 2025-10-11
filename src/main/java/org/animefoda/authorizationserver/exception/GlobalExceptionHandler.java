package org.animefoda.authorizationserver.exception;

import exception.BadCredentialsException;
import exception.BaseError;
import exception.ErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import response.ApiResponse;

@ControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(BaseError.class)
    public ResponseEntity<ApiResponse<Object>> handleBaseError(BaseError baseError) {
        ApiResponse<Object> response = ApiResponse.error(baseError.getMessage(), baseError.getErrorCode());
//        baseError.printStackTrace();
        return new ResponseEntity<>(response, HttpStatusCode.valueOf(baseError.getErrorCode().getHttpStatusCode()));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<Object>> handleBadCredentialsException(BadCredentialsException badCredentialsException) {
        ApiResponse<Object> response = ApiResponse.error(badCredentialsException.getMessage(), badCredentialsException.getErrorCode());
        return new  ResponseEntity<>(response, HttpStatusCode.valueOf(badCredentialsException.getErrorCode().getHttpStatusCode()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Object>> handleException(Exception ex) {
        ApiResponse<Object> response = ApiResponse.error(
                ex.getMessage(),
                ErrorCode.INTERNAL_SERVER_ERROR
        );
//        ex.printStackTrace();
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Object>> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(err -> err.getField() + ": " + err.getDefaultMessage())
                .findFirst()
                .orElse("Validation error");

        return new ResponseEntity<>(ApiResponse.error(message, ErrorCode.VALIDATION_ERROR), HttpStatus.BAD_REQUEST);
    }

//    @ExceptionHandler(BadRequestException.class)
//    public ResponseEntity<ApiResponse<Object>> handleBadRequest(BadRequestException ex) {
//        ApiResponse<Object> response = ApiResponse.error(ex.getMessage()+ " " + ex.getUserError(), ex.getErrorCode());
//        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
//    }

}
