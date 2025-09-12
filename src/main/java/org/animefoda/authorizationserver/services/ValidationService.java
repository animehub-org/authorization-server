package org.animefoda.authorizationserver.services;

import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

@Service
public class ValidationService {

    public boolean validateEmail(String email) {
        Pattern regexPattern = Pattern.compile("^(?=.{1,64}@)[A-Za-z0-9\\+_-]+(\\.[A-Za-z0-9\\+_-]+)*@"
                + "[^-][A-Za-z0-9\\+-]+(\\.[A-Za-z0-9\\+-]+)*(\\.[A-Za-z]{2,})$");
        return regexPattern.matcher(email).matches();
    }

    public boolean validateUsername(String username){
        Pattern regexPattern = Pattern.compile("");
        return regexPattern.matcher(username).matches();
    }
}
