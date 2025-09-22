package org.animefoda.authorizationserver.controllers;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import org.animefoda.authorizationserver.annotation.DecryptedBody;
import org.animefoda.authorizationserver.entities.role.Role;
import org.animefoda.authorizationserver.entities.role.RoleName;
import org.animefoda.authorizationserver.entities.role.RoleService;
import org.animefoda.authorizationserver.entities.user.*;
import org.animefoda.authorizationserver.entities.usersession.UserSession;
import org.animefoda.authorizationserver.entities.usersession.UserSessionService;
import org.animefoda.authorizationserver.exception.BadCredentialsException;
import org.animefoda.authorizationserver.exception.BaseError;
import org.animefoda.authorizationserver.request.*;
import org.animefoda.authorizationserver.response.*;
import org.animefoda.authorizationserver.services.*;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

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
    private final RoleService roleService;

    AuthController(
            UserSessionService userSessionService,
            UserService userService,
            BCryptPasswordEncoder bCryptPasswordEncoder,
            ReCaptchaService reCaptchaService,
            KeysService keysService,
            ValidationService validationService,
            JWTService jwtService, RoleService roleService) {
        this.userSessionService = userSessionService;
        this.userService = userService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.reCaptchaService = reCaptchaService;
        this.keysService = keysService;
        this.validationService = validationService;
        this.jwtService = jwtService;
        this.roleService = roleService;
    }

    @PostMapping("/login")
    @Transactional
    public ApiResponse<TokenResponse> login(
        @DecryptedBody @RequestBody LoginRequest request,
        @RequestHeader("User-Agent") String userAgent,
        HttpServletResponse response
    ) throws Exception {
        System.out.println(request.toString());
        User user = this.checkLoginValue(request.loginValue());
        if (!user.isLoginCorrect(request.password(), bCryptPasswordEncoder)) throw new BadCredentialsException();

        UserSession session = this.createAndSaveSession(user, userAgent, request.fingerprint());

        String accessToken = jwtService.generateAccessToken(session);
        String refreshToken = jwtService.generateRefreshToken(session);

        Cookie cookie = this.createCookie(accessToken);

        response.addCookie(cookie);
        return ApiResponse.setSuccess(new TokenResponse(accessToken, refreshToken, jwtService.getAccessExpirationTimeMs(), user.toUserDTO()));
    }

    private Cookie createCookie(String accessToken){
        Cookie cookie = new Cookie("accessToken", accessToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
        cookie.setPath("/");
        cookie.setMaxAge((int) (jwtService.getAccessExpirationTimeMs() / 1000));
        return cookie;
    }

    private UserSession createAndSaveSession(User user, String userAgent, String fingerprint){
        UserSession session = userSessionService.createSession(user);
        session.setUserAgent(userAgent);
        session.setFingerprint(fingerprint);

        return session;
//        return userSessionService.save(session);
    }

    private User checkLoginValue(String loginValue) throws BadCredentialsException {
        User user;
        if(this.validationService.validateEmail(loginValue)){
            user = userService.findByEmail(loginValue).orElseThrow(BadCredentialsException::new);
        }else if(this.validationService.validateUsername(loginValue)){
            user = userService.findByUsername(loginValue).orElseThrow(BadCredentialsException::new);
        }else{
            throw new BadCredentialsException();
        }
        return user;
    }

//    @PostMapping("/admin/login")
//    public ApiResponse<TokenResponse> adminLogin(
//        @DecryptedBody @RequestBody LoginRequest body,
//        @RequestHeader("User-Agent") String userAgent,
//        HttpServletResponse response
//    ){
//        User user = this.checkLoginValue(body.loginValue());
//        if (!user.isLoginCorrect(body.password(), bCryptPasswordEncoder)) throw new BadCredentialsException();
//
//        UserSession session = this.createAndSaveSession(user, userAgent, body.fingerprint());
//
//        String accessToken = jwtService.generateAccessToken(session);
//        String refreshToken = jwtService.generateRefreshToken(session);
//
//        Cookie cookie = this.createCookie(accessToken);
//
//        response.addCookie(cookie);
//        return ApiResponse.setSuccess(new TokenResponse(accessToken, refreshToken, jwtService.getAccessExpirationTimeMs()));
//    }

    @PostMapping("/register")
    @Transactional
    public ApiResponse<UserDTO> register(
        @DecryptedBody @RequestBody RegisterRequest body
    ) throws BaseError {
        String salt  = BCrypt.gensalt();
        String password = BCrypt.hashpw(body.password(), salt);

        List<Role> roles = new ArrayList<>();
        roles.add(roleService.findByName(RoleName.ROLE_USER).orElseThrow());

        if(!this.validationService.validateUsername(body.username())){
            throw new BadCredentialsException();
        }
        if(!this.validationService.validateEmail(body.email())){
            throw new BadCredentialsException();
        }

        User user  = new User(
            body.birthDate(),
            body.name(),
            body.surname(),
            body.username(),
            body.email(),
            password,
            salt,
            false,
            roles
        );

        User savedUser = this.userService.save(user);

        return ApiResponse.setSuccess(savedUser.toUserDTO());
    }
}
