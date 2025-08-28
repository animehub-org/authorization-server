package org.animefoda.authorizationserver.request;

public record UserFingerprint(
    String WebGLVendor,
    String WebGLRenderer,
    String timeZone
) {
}
