package org.animefoda.authorizationserver.exception;

public class AlreadyExistsException extends BaseError {
    public AlreadyExistsException(String type) {
        super(type+ " already exists ", ErrorCode.EXISTS);
    }
}
