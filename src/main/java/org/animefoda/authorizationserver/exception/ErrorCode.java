package org.animefoda.authorizationserver.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {
    NOT_FOUND(HttpStatus.NOT_FOUND),
    BAD_REQUEST(HttpStatus.BAD_REQUEST),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED),
    FORBIDDEN(HttpStatus.FORBIDDEN),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR),
    VALIDATION_ERROR(HttpStatus.BAD_REQUEST),
    INVALID_CAPTCHA(HttpStatus.UNPROCESSABLE_ENTITY),
    INVALID_TOKEN(HttpStatus.UNAUTHORIZED),
    EXISTS(HttpStatus.CONFLICT);

    private final HttpStatus httpStatus;

    ErrorCode(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }

}
