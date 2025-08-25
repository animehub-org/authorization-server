package org.animefoda.authorizationserver.controllers;

import org.animefoda.authorizationserver.request.LoginRequest;
import org.animefoda.authorizationserver.response.ApiResponse;
import org.animefoda.authorizationserver.response.TokenResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

@RestController
@RequestMapping("/")
class AuthController {
    @PostMapping("login")
    public ApiResponse<TokenResponse> login(
        @RequestBody LoginRequest body
    ){

        return new ApiResponse<>(new TokenResponse("",""));
    }
}
