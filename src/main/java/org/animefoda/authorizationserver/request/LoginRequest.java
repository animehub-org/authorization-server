package org.animefoda.authorizationserver.request;

import org.jetbrains.annotations.NotNull;

public record LoginRequest(
    String loginValue,
    String password,
    String fingerprint
) {
    @NotNull
    @Override
    public String toString() {
        return "LoginRequest{" +
                "loginValue='" + loginValue + '\'' +
                ", password='" + password + '\'' +
                ", fingerprint='" + fingerprint + '\'' +
                '}';
    }
}
