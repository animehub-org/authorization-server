package org.animefoda.authorizationserver.controllers;

import jakarta.servlet.http.HttpServletRequest;
import org.animefoda.authorizationserver.entities.user.User;
import org.animefoda.authorizationserver.entities.user.UserRepository;
import org.animefoda.authorizationserver.entities.user.UserService;
import org.animefoda.authorizationserver.entities.usersession.UserSession;
import org.animefoda.authorizationserver.entities.usersession.UserSessionService;
import org.animefoda.authorizationserver.exception.BadCredentialsException;
import org.animefoda.authorizationserver.request.LoginRequest;
import org.animefoda.authorizationserver.response.ApiResponse;
import org.animefoda.authorizationserver.response.TokenResponse;
import org.animefoda.authorizationserver.services.ReCaptchaService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.UUID;

@RestController
@RequestMapping("/")
class AuthController {

    private final UserSessionService userSessionService;
    private final UserService userService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ReCaptchaService reCaptchaService;

    public AuthController(
            UserSessionService userSessionService,
            UserService userService,
            BCryptPasswordEncoder bCryptPasswordEncoder,
            ReCaptchaService reCaptchaService
        ) {
        this.userSessionService = userSessionService;
        this.userService = userService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.reCaptchaService = reCaptchaService;
    }
    @PostMapping("login")
    public ApiResponse<TokenResponse> login(
        @RequestBody LoginRequest body,
        @RequestHeader("User-Agent") String userAgent
    ) throws IOException {
        reCaptchaService.processResponse(body.recaptchaValue());

        User user = userService.findByEmail(body.email()).orElseThrow(BadCredentialsException::new);
        if(!user.isLoginCorrect(body.password(), bCryptPasswordEncoder)) throw new BadCredentialsException();



        UserSession session = userSessionService.createSession(user);
        session.setTimeZone(body.fingerprint().timeZone());
        session.setUserAgent(userAgent);
        session.setWebGlRenderer(body.fingerprint().WebGLRenderer());
        session.setWebGlVendor(body.fingerprint().WebGLVendor());

        userSessionService.save(session);


        return new ApiResponse<>(new TokenResponse("",""));
    }
}
