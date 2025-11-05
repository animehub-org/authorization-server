package org.animefoda.authorizationserver.advice;

import entities.user.User;
import exception.BadCredentialsException;
import jakarta.servlet.http.HttpServletRequest;
import org.animefoda.authorizationserver.annotation.CurrentUser;
import org.animefoda.authorizationserver.services.JWTService;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import services.UserService;

import java.util.UUID;

@Component
public class CurrentUserArgumentResolver implements HandlerMethodArgumentResolver {
    private final UserService userService;
    private final JWTService jwtService; // <-- Adicione o JWTService

    // Atualize o construtor
    public CurrentUserArgumentResolver(UserService userService, JWTService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService; // <-- Adicione o JWTService
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterType().equals(User.class) &&
                parameter.hasParameterAnnotation(CurrentUser.class);
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        HttpServletRequest request = webRequest.getNativeRequest(HttpServletRequest.class);
        if(request == null){
            throw new BadCredentialsException("HTTP Request is not accessible");
        }
        String authHeader = request.getHeader("Authorization");

        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            throw new BadCredentialsException("Missing token Bearer or malformed Bearer Token");
        }
        String token = authHeader.substring(7);

        UUID userId;
        try{
            userId = jwtService.extractSubject(token);
        }catch (Exception e){
            throw new BadCredentialsException("Invalid token or expired"+ e.getMessage());
        }

        if(userId == null){
            throw new BadCredentialsException("User ID subject not found");
        }

        return userService.findById(userId)
                .orElseThrow(() -> new BadCredentialsException("User not found"));
    }
}
