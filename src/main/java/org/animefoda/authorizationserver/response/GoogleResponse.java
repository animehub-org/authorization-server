package org.animefoda.authorizationserver.response;

import org.jetbrains.annotations.NotNull;

import java.time.Instant;

public record GoogleResponse(
    boolean success,
    @NotNull
    Instant challenge_ts,
    String hostname
) {
}
