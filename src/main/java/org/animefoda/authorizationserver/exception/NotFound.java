package org.animefoda.authorizationserver.exception;

public class NotFound extends BaseError{
    public NotFound(String message) {
        super(message, ErrorCode.NOT_FOUND);
    }
}
