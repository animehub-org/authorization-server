package org.animefoda.authorizationserver.exception;

public class InvalidReCaptchaException extends BaseError {
    public InvalidReCaptchaException(String message) {
        super(message,ErrorCode.INVALID_CAPTCHA);
    }
}
