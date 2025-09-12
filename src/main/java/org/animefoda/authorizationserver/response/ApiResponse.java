package org.animefoda.authorizationserver.response;

import org.animefoda.authorizationserver.exception.ErrorCode;

import java.io.Serializable;
import java.time.Instant;

public record ApiResponse<T>(
    boolean success,
    T data,
    String message,
    Instant timestamp,
    ErrorCode errorCode
) implements Serializable {
    public ApiResponse(T data){
        this(true, data, null, Instant.now(), null);
    }
    public ApiResponse(boolean success, String message){
        this(success, null, message, Instant.now(), null);
    }
    public ApiResponse(T data, String message){
        this(true, data, message, Instant.now(), null);
    }
    public ApiResponse(String message, ErrorCode errorCode){
        this(false, null, message, Instant.now(), errorCode);
    }

    public static <T> ApiResponse<T> error(String message, ErrorCode errorCode){
        return new ApiResponse<>(message, errorCode);
    }

    public static <T> ApiResponse<T> setSuccess(T data, String message){
        return new ApiResponse<>(data, message);
    }
    public static <T> ApiResponse<T> setSuccess(T data) {
        return new ApiResponse<>(data);
    }
}
