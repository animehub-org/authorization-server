package org.animefoda.authorizationserver.advice;

import com.fasterxml.jackson.databind.ObjectMapper;
import exception.BadRequestException;
import exception.ReCaptchaException;
import org.animefoda.authorizationserver.annotation.DecryptedBody;
import org.animefoda.authorizationserver.request.LoginEncrypted;
import org.animefoda.authorizationserver.services.KeysService;
import org.animefoda.authorizationserver.services.ReCaptchaService;
import org.jetbrains.annotations.NotNull;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;

@ControllerAdvice
public class DecryptionAdvice implements RequestBodyAdvice {
    private final KeysService keysService;
    private final ObjectMapper objectMapper;
    private final ReCaptchaService reCaptchaService;

    public DecryptionAdvice(KeysService keysService, ObjectMapper objectMapper, ReCaptchaService reCaptchaService) {
        this.keysService = keysService;
        this.objectMapper = objectMapper;
        this.reCaptchaService = reCaptchaService;
    }

    @Override
    public boolean supports(MethodParameter methodParameter, Type type, Class<? extends HttpMessageConverter<?>> converterType){
        return methodParameter.hasParameterAnnotation(DecryptedBody.class);
    }

    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage inputMessage, MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) throws IOException {
        try {
            LoginEncrypted encryptedBody = objectMapper.readValue(inputMessage.getBody(), LoginEncrypted.class);

            if (encryptedBody.recaptchaToken() == null) {
                throw new BadRequestException("Recaptcha token is missing", "RECAPTCHA_TOKEN_MISSING");
            }
            reCaptchaService.processResponse(encryptedBody.recaptchaToken());

            Object decryptedPayload = keysService.decryptAndDeserialize(
                    encryptedBody.encryptedInfo(), (Class<?>) targetType
            );

            String decryptedJson = objectMapper.writeValueAsString(decryptedPayload);
            return new DecryptedInputMessage(decryptedJson, inputMessage.getHeaders());

        }
        catch (BadRequestException | ReCaptchaException e) {
            throw e;
        }
        catch (Exception e) {
            throw new BadRequestException("Decryption or deserialization failed", e.getMessage());
        }
    }

    @NotNull
    @Override
    public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }

    @Override
    public Object handleEmptyBody(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        throw new BadRequestException("No body", "NO_BODY");
    }

    private static class DecryptedInputMessage implements HttpInputMessage {
        private final InputStream body;
        private final HttpHeaders headers;

        public DecryptedInputMessage(String body, HttpHeaders headers) {
            this.body = new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
            this.headers = headers;
        }

        @NotNull
        @Override
        public InputStream getBody() {
            return body;
        }

        @NotNull
        @Override
        public HttpHeaders getHeaders() {
            return headers;
        }
    }
}
