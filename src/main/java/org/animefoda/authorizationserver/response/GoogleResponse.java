package org.animefoda.authorizationserver.response;

import org.jetbrains.annotations.NotNull;

import java.time.Instant;
import java.util.Date;

public record GoogleResponse(
    boolean success,
    Date challenge_ts,
    String hostname
) {
    @Override
    public String toString() {
        return "GoogleResponse{" +
                "success=" + success +
                ", challenge_ts=" + challenge_ts +
                ", hostname='" + hostname + '\'' +
                '}';
    }
}
