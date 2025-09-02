package org.animefoda.authorizationserver.services;

import jakarta.servlet.http.HttpServletRequest;
import org.animefoda.authorizationserver.config.ReCaptchaConfiguration;
import org.animefoda.authorizationserver.exception.InvalidReCaptchaException;
import org.animefoda.authorizationserver.response.GoogleResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Pattern;

@Service
public class ReCaptchaService {
    private final ReCaptchaConfiguration reCaptchaConfiguration;

    @Autowired
    public ReCaptchaService( ReCaptchaConfiguration reCaptchaConfiguration) {
        this.reCaptchaConfiguration = reCaptchaConfiguration;

    }

    private static final String GOOGLE_RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    private static Pattern RESPONSE_PATTERN = Pattern.compile("[A-Za-z0-9-_]+");

    public void processResponse(String response) throws IOException {
        if(!this.responseSanityCheck(response)){
            throw new InvalidReCaptchaException("Response contains invalid characters");
        }

        String remoteIP = this.getClientIpAddress();

        URL url = new URL(GOOGLE_RECAPTCHA_VERIFY_URL + "?secret=" + reCaptchaConfiguration.getSecret() + "&response=" + response + "&remoteip=" + remoteIP);

        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setRequestMethod("POST");

        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream())
        );
        String inputLine;
        StringBuffer content = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
    }

    private boolean responseSanityCheck(String response){
        return RESPONSE_PATTERN.matcher(response).matches();
    }

    private String getClientIpAddress(){
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

        String xForwardedForHeader = request.getHeader("X-Forwarded-For");
        if(xForwardedForHeader != null && !xForwardedForHeader.isEmpty()){
            return xForwardedForHeader.split(",")[0];
        }
        return request.getRemoteAddr();
    }
}
