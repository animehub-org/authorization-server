package org.animefoda.authorizationserver.exception;

import org.animefoda.authorizationserver.response.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(BaseError.class)
    public ResponseEntity<ApiResponse> handleBaseError(BaseError baseError) {
        ApiResponse<Object> response = ApiResponse.error(baseError.getMessage(), baseError.getErrorCode());
        baseError.printStackTrace();
        return new ResponseEntity<>(response, baseError.errorCode.getHttpStatus());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse> handleBadCredentialsException(BadCredentialsException badCredentialsException) {
        ApiResponse<Object> response = ApiResponse.error(badCredentialsException.getMessage(), badCredentialsException.getErrorCode());
        return new  ResponseEntity<>(response, badCredentialsException.errorCode.getHttpStatus());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Object>> handleException(Exception ex) {
        ApiResponse<Object> response = ApiResponse.error(
                ex.getMessage(),
                ErrorCode.INTERNAL_SERVER_ERROR
        );
        ex.printStackTrace();
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
