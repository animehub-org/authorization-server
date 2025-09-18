package org.animefoda.authorizationserver.controllers;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.animefoda.authorizationserver.annotation.DecryptedBody;
import org.animefoda.authorizationserver.entities.user.*;
import org.animefoda.authorizationserver.entities.usersession.UserSession;
import org.animefoda.authorizationserver.entities.usersession.UserSessionService;
import org.animefoda.authorizationserver.exception.BadCredentialsException;
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
        @DecryptedBody @RequestBody LoginRequest request,
        @RequestHeader("User-Agent") String userAgent,
        HttpServletResponse response
    ) throws Exception {
        System.out.println(request.toString());
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
    public ApiResponse<UserDTO> register(
        @RequestBody LoginEncrypted body
    ){

        return ApiResponse.setSuccess(null);
    }
}
