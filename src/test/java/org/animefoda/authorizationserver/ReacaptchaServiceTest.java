package org.animefoda.authorizationserver;

import org.animefoda.authorizationserver.config.ReCaptchaConfiguration;
import org.animefoda.authorizationserver.services.ReCaptchaService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;

@ExtendWith(MockitoExtension.class)
public class ReacaptchaServiceTest {

    @Mock
    private ReCaptchaConfiguration reCaptchaConfiguration;

    @InjectMocks
    private ReCaptchaService reCaptchaService;

    @Test
    void googleRecaptchaTest() throws IOException {
        this.reCaptchaService.processResponse("");
    }
}
