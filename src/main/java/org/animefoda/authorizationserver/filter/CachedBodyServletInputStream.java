package org.animefoda.authorizationserver.filter;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class CachedBodyServletInputStream extends ServletInputStream {
    private final InputStream cachedBody;

    public CachedBodyServletInputStream(InputStream originalBody) throws IOException {
        // Leia o corpo original e o armazene em um ByteArrayInputStream
        this.cachedBody = new ByteArrayInputStream(originalBody.readAllBytes());
    }

    @Override
    public boolean isFinished() {
        try {
            return cachedBody.available() == 0;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public void setReadListener(ReadListener readListener) {
        throw new RuntimeException("Not yet implemented");
    }

    @Override
    public int read() throws IOException {
        return cachedBody.read();
    }
}
