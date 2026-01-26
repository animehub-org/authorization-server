package org.animefoda.authorizationserver.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * Converter para autenticação de clientes públicos (sem secret).
 * Extrai o client_id do body da requisição para clientes com
 * ClientAuthenticationMethod.NONE
 */
public class PublicClientAuthenticationConverter implements AuthenticationConverter {

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        // Verifica se tem client_id no body
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId)) {
            return null;
        }

        // Verifica se NÃO tem client_secret (característica de cliente público)
        String clientSecret = request.getParameter(OAuth2ParameterNames.CLIENT_SECRET);
        if (StringUtils.hasText(clientSecret)) {
            // Se tem secret, deixa outro converter tratar
            return null;
        }

        // Retorna token de autenticação para cliente público
        return new OAuth2ClientAuthenticationToken(
                clientId,
                ClientAuthenticationMethod.NONE,
                null,
                null);
    }
}
