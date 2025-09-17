package org.animefoda.authorizationserver.controllers;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.animefoda.authorizationserver.entities.user.*;
import org.animefoda.authorizationserver.entities.usersession.UserSession;
import org.animefoda.authorizationserver.entities.usersession.UserSessionService;
import org.animefoda.authorizationserver.exception.BadCredentialsException;
import org.animefoda.authorizationserver.exception.BadRequestException;
import org.animefoda.authorizationserver.exception.ReCaptchaException;
import org.animefoda.authorizationserver.request.*;
import org.animefoda.authorizationserver.response.*;
import org.animefoda.authorizationserver.services.*;
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
    private final ValidationService validationService;
    private final JWTService jwtService;

    AuthController(
            UserSessionService userSessionService,
            UserService userService,
            BCryptPasswordEncoder bCryptPasswordEncoder,
            ReCaptchaService reCaptchaService,
            KeysService keysService,
            ValidationService validationService,
            JWTService jwtService) {
        this.userSessionService = userSessionService;
        this.userService = userService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.reCaptchaService = reCaptchaService;
        this.keysService = keysService;
        this.validationService = validationService;
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public ApiResponse<TokenResponse> login(
        @RequestBody LoginEncrypted body,
        @RequestHeader("User-Agent") String userAgent,
        HttpServletResponse response
    ) throws Exception {
        if (body.encryptedInfo() == null) throw new BadRequestException("Request error", "Encrypted info is null");
        if (body.recaptchaToken() == null) throw new BadRequestException("Request error", "Recaptcha token is null");
        LoginRequest request = keysService.decryptAndDeserialize(body.encryptedInfo(), LoginRequest.class);
        GoogleResponse googleResponse = reCaptchaService.processResponse(body.recaptchaToken());
        if (!googleResponse.success()) {
            throw new ReCaptchaException();
        }
        User user;

        if(this.validationService.validateEmail(request.loginValue())){
            user = userService.findByEmail(request.loginValue()).orElseThrow(BadCredentialsException::new);
        }else if(this.validationService.validateUsername(request.loginValue())){
            user = userService.findByUsername(request.loginValue()).orElseThrow(BadCredentialsException::new);
        }else{
            throw new BadCredentialsException();
        }

        if (!user.isLoginCorrect(request.password(), bCryptPasswordEncoder)) throw new BadCredentialsException();

        UserSession session = userSessionService.createSession(user);
        session.setUserAgent(userAgent);
        session.setFingerprint(request.fingerprint());

        userSessionService.save(session);

        String accessToken = jwtService.generateAccessToken(session);
        String refreshToken = jwtService.generateRefreshToken(session);

        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge((int) (jwtService.getRefreshExpirationTimeMs() / 1000));
        String cookieHeader = String.format("%s; SameSite=Lax", cookie.getValue());
        response.addHeader("Set-Cookie", cookieHeader);
        return ApiResponse.setSuccess(new TokenResponse(accessToken, refreshToken, jwtService.getAccessExpirationTimeMs()));
    }

    @PostMapping("/register")
    public ApiResponse<UserDTO> register(){
        return ApiResponse.setSuccess(null);
    }
}
