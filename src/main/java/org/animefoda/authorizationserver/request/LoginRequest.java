package org.animefoda.authorizationserver.request;

public record LoginRequest(
    String email,
    String username,
    String password,
    String fingerprint
) {
    @Override
    public String toString() {
        return "LoginRequest{" +
                "email='" + email + '\'' +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", fingerprint=" + fingerprint +
                '}';
    }
}
