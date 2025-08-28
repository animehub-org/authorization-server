package org.animefoda.authorizationserver.exception;

public class BadCredentialsException extends BaseError {
    public BadCredentialsException() {
        super("Invalid email or password", ErrorCode.VALIDATION_ERROR);
    }
}
