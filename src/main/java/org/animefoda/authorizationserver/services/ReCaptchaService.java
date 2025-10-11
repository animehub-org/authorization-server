package org.animefoda.authorizationserver.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import exception.InvalidReCaptchaException;
import jakarta.servlet.http.HttpServletRequest;
import org.animefoda.authorizationserver.config.ReCaptchaConfiguration;
import org.animefoda.authorizationserver.response.GoogleResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

@Service
public class ReCaptchaService {
    private final ReCaptchaConfiguration reCaptchaConfiguration;
    private final ObjectMapper objectMapper;

    @Autowired
    public ReCaptchaService( ReCaptchaConfiguration reCaptchaConfiguration) {
        this.reCaptchaConfiguration = reCaptchaConfiguration;
        this.objectMapper = new ObjectMapper();

    }

    private static final String GOOGLE_RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    private static final Pattern RESPONSE_PATTERN = Pattern.compile("[A-Za-z0-9-_]+");

    public GoogleResponse processResponse(String response) throws IOException, InvalidReCaptchaException {
        if (response == null) {
            throw new InvalidReCaptchaException("reCAPTCHA response is null.");
        }
        if(!this.responseSanityCheck(response)){
            throw new InvalidReCaptchaException("Response contains invalid characters");
        }

        String remoteIP = this.getClientIpAddress();

        URL url = new URL(GOOGLE_RECAPTCHA_VERIFY_URL );

        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setRequestMethod("POST");

        con.setDoOutput(true);

        String postParams = "secret=" + reCaptchaConfiguration.getSecret() +
                "&response=" + response +
                "&remoteip=" + remoteIP;

        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        con.setRequestProperty("Content-Length", String.valueOf(postParams.length()));

        try (OutputStream os = con.getOutputStream()) {
            byte[] input = postParams.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

        // The rest of your code to read the response remains the same
        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream())
        );
        String inputLine;
        StringBuilder content = new StringBuilder();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        return this.objectMapper.readValue(content.toString(), GoogleResponse.class);
    }

    private boolean responseSanityCheck(String response){
        return StringUtils.hasText(response)&&RESPONSE_PATTERN.matcher(response).matches();
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
