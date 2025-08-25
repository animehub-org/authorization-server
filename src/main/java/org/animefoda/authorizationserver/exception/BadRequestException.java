package org.animefoda.authorizationserver.exception;

import lombok.Getter;

@Getter
public class BadRequestException extends BaseError {
    private final String userError;

    public BadRequestException(String message, String userError) {
        super(message, ErrorCode.BAD_REQUEST);
        this.userError = userError;
    }
}
