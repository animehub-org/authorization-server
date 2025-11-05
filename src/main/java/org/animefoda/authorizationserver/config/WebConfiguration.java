package org.animefoda.authorizationserver.config;

import org.animefoda.authorizationserver.advice.CurrentUserArgumentResolver;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer; // 1. Importe a interface

import java.util.List;

@Configuration
public class WebConfiguration implements WebMvcConfigurer { // 2. Adicione "implements WebMvcConfigurer"

    private final CurrentUserArgumentResolver currentUserArgumentResolver;

    public WebConfiguration(CurrentUserArgumentResolver currentUserArgumentResolver) {
        this.currentUserArgumentResolver = currentUserArgumentResolver;
    }

    // 3. Agora a anotação @Override é válida
    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(currentUserArgumentResolver);
    }
}