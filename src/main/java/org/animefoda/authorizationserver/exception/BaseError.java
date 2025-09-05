package org.animefoda.authorizationserver.exception;

import lombok.Getter;

@Getter
public abstract class BaseError extends RuntimeException {
    protected final ErrorCode errorCode;
    public BaseError(String message, ErrorCode errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

}
