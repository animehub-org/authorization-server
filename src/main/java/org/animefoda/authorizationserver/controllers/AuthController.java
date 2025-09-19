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

        UserSession savedSession = userSessionService.save(session);

        String accessToken = jwtService.generateAccessToken(savedSession);
        String refreshToken = jwtService.generateRefreshToken(savedSession);

        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
        cookie.setPath("/");
        cookie.setMaxAge((int) (jwtService.getRefreshExpirationTimeMs() / 1000));
//        cookie.setAttribute("SameSite", "Lax");
        response.addCookie(cookie);
        return ApiResponse.setSuccess(new TokenResponse(accessToken, refreshToken, jwtService.getAccessExpirationTimeMs()));
    }

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
