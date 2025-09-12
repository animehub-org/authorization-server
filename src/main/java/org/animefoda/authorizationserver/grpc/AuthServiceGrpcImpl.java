package org.animefoda.authorizationserver.grpc;

import org.animefoda.authorizationserver.services.KeysService;

public class AuthServiceGrpcImpl extends org.animefoda.grpc.auth.AuthServiceGrpc.AuthServiceImplBase{
    private final KeysService keysService;

    public AuthServiceGrpcImpl(KeysService keysService) {
        this.keysService = keysService;
    }

}
