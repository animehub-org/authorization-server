package org.animefoda.authorizationserver.handler;

import entities.user.User;
import entities.usersession.UserSession;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.animefoda.authorizationserver.services.JWTService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import services.UserService;
import services.UserSessionService;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Component
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final UserService userService;
    private final UserSessionService userSessionService;
    private final JWTService jwtService;

    @Value("${oauth2.success.redirect-uri:http://localhost:5173/oauth2/callback}")
    private String redirectUri;

    public OAuth2AuthenticationSuccessHandler(
            UserService userService,
            UserSessionService userSessionService,
            JWTService jwtService) {
        this.userService = userService;
        this.userSessionService = userSessionService;
        this.jwtService = jwtService;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String userIdStr = oAuth2User.getAttribute("userId");
        if (userIdStr == null) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "User ID not found");
            return;
        }

        UUID userId = UUID.fromString(userIdStr);
        User user = userService.findById(userId).orElseThrow();

        // Cria sessão e gera tokens
        String userAgent = request.getHeader("User-Agent");
        String fingerprint = request.getParameter("fingerprint");

        UserSession session = userSessionService.createSession(user);
        session.setUserAgent(userAgent != null ? userAgent : "OAuth2-Login");
        session.setFingerprint(fingerprint != null ? fingerprint : "google-oauth2");
        userSessionService.save(session);

        String accessToken = jwtService.generateAccessToken(session);
        String refreshToken = jwtService.generateRefreshToken(session);

        // Redireciona para o frontend com os tokens
        String redirectUrl = String.format(
                "%s?access_token=%s&refresh_token=%s&expires_in=%d",
                redirectUri,
                URLEncoder.encode(accessToken, StandardCharsets.UTF_8),
                URLEncoder.encode(refreshToken, StandardCharsets.UTF_8),
                jwtService.getAccessExpirationTimeMs() / 1000);

        response.sendRedirect(redirectUrl);
    }
}
