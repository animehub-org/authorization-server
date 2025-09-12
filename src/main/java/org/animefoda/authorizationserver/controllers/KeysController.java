package org.animefoda.authorizationserver.controllers;

import org.animefoda.authorizationserver.response.ApiResponse;
import org.animefoda.authorizationserver.services.KeysService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.PublicKey;

@RestController
@RequestMapping("/g/keys")
public class KeysController {
    private final KeysService service;

    public KeysController(KeysService service) {
        this.service = service;
    }

    @GetMapping("public")
    public ApiResponse<String> getPublicKey() {
        return ApiResponse.setSuccess(service.getPublicAsBase64());
    }

}
