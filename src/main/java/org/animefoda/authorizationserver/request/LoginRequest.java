package org.animefoda.authorizationserver.request;

public record LoginRequest(
    String loginValue,
    String password,
    String fingerprint
) {
    @Override
    public String toString() {
        return "LoginRequest{" +
                "loginValue='" + loginValue + '\'' +
                ", password='" + password + '\'' +
                ", fingerprint='" + fingerprint + '\'' +
                '}';
    }
}
