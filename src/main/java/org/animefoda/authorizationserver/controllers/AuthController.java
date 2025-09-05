package org.animefoda.authorizationserver.controllers;

import org.animefoda.authorizationserver.entities.user.User;
import org.animefoda.authorizationserver.entities.user.UserService;
import org.animefoda.authorizationserver.entities.usersession.UserSession;
import org.animefoda.authorizationserver.entities.usersession.UserSessionService;
import org.animefoda.authorizationserver.exception.BadCredentialsException;
import org.animefoda.authorizationserver.exception.BadRequestException;
import org.animefoda.authorizationserver.exception.ReCaptchaException;
import org.animefoda.authorizationserver.request.LoginEncrypted;
import org.animefoda.authorizationserver.request.LoginRequest;
import org.animefoda.authorizationserver.response.ApiResponse;
import org.animefoda.authorizationserver.response.GoogleResponse;
import org.animefoda.authorizationserver.response.TokenResponse;
import org.animefoda.authorizationserver.services.KeysService;
import org.animefoda.authorizationserver.services.ReCaptchaService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
//@RequestMapping("/")
class AuthController {

    private final UserSessionService userSessionService;
    private final UserService userService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ReCaptchaService reCaptchaService;
    private final KeysService keysService;

    public AuthController(
            UserSessionService userSessionService,
            UserService userService,
            BCryptPasswordEncoder bCryptPasswordEncoder,
            ReCaptchaService reCaptchaService,
            KeysService keysService
        ) {
        this.userSessionService = userSessionService;
        this.userService = userService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.reCaptchaService = reCaptchaService;
        this.keysService = keysService;
    }
    @PostMapping("/login")
    public ApiResponse<TokenResponse> login(
        @RequestBody LoginEncrypted body,
        @RequestHeader("User-Agent") String userAgent
    ) throws Exception {
        if(body.encryptedInfo() == null) throw new BadRequestException("Request error", "Encrypted info is null");
        if(body.recaptchaToken() == null) throw new BadRequestException("Request error", "Recaptcha token is null");
        LoginRequest request = keysService.decryptAndDeserialize(body.encryptedInfo(), LoginRequest.class);
        GoogleResponse googleResponse = reCaptchaService.processResponse(body.recaptchaToken());
        if(!googleResponse.success()){
            throw new ReCaptchaException();
        }

        User user = userService.findByEmail(request.email()).orElseThrow(BadCredentialsException::new);
        if(!user.isLoginCorrect(request.password(), bCryptPasswordEncoder)) throw new BadCredentialsException();


        UserSession session = userSessionService.createSession(user);
        session.setUserAgent(userAgent);
        session.setFingerprint(request.fingerprint());

        userSessionService.save(session);

        return new ApiResponse<>(new TokenResponse("",""));
    }
}
