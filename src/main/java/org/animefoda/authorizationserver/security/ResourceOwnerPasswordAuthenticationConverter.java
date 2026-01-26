package org.animefoda.authorizationserver.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;

/**
 * Converts HTTP request to ResourceOwnerPasswordAuthenticationToken.
 * Extracts username, password, and scopes from the token request.
 */
public class ResourceOwnerPasswordAuthenticationConverter implements AuthenticationConverter {

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        // Check grant_type
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!"password".equals(grantType)) {
            return null;
        }

        // Get client authentication
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        // Extract parameters
        MultiValueMap<String, String> parameters = getParameters(request);

        // Validate username
        String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
        if (!StringUtils.hasText(username) || parameters.get(OAuth2ParameterNames.USERNAME).size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        // Validate password
        String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);
        if (!StringUtils.hasText(password) || parameters.get(OAuth2ParameterNames.PASSWORD).size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        // Extract scopes
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        Set<String> requestedScopes = null;
        if (StringUtils.hasText(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() == 1) {
            requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        // Build additional parameters (exclude standard OAuth2 params)
        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(OAuth2ParameterNames.USERNAME) &&
                    !key.equals(OAuth2ParameterNames.PASSWORD) &&
                    !key.equals(OAuth2ParameterNames.SCOPE) &&
                    !key.equals(OAuth2ParameterNames.CLIENT_ID)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        // Add User-Agent if present
        String userAgent = request.getHeader("User-Agent");
        if (StringUtils.hasText(userAgent)) {
            additionalParameters.put("userAgent", userAgent);
        }

        return new ResourceOwnerPasswordAuthenticationToken(
                username, password, clientPrincipal, requestedScopes, additionalParameters);
    }

    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            for (String value : values) {
                parameters.add(key, value);
            }
        });
        return parameters;
    }
}
