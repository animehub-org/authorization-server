package org.animefoda.authorizationserver.grpc;

import io.grpc.stub.StreamObserver;
import org.animefoda.authorizationserver.services.KeysService;
import org.animefoda.grpc.auth.DecryptRequest;
import org.animefoda.grpc.auth.DecryptResponse;
import org.animefoda.grpc.auth.DecryptServiceGrpc;
import org.springframework.grpc.server.service.GrpcService;

@GrpcService
public class DecryptGrpcService extends DecryptServiceGrpc.DecryptServiceImplBase {

    private final KeysService keysService;

    public DecryptGrpcService(KeysService keysService) {
        this.keysService = keysService;
    }

    @Override
    public void decrypt(DecryptRequest request, StreamObserver<DecryptResponse> responseObserver) {
        try {
            String encryptedData = request.getEncryptedData();

            // Desencripta os dados usando a chave privada do auth-server
            String decryptedData = keysService.decryptBase64(encryptedData);

            DecryptResponse response = DecryptResponse.newBuilder()
                    .setSuccess(true)
                    .setDecryptedData(decryptedData)
                    .build();

            responseObserver.onNext(response);
            responseObserver.onCompleted();

        } catch (Exception e) {
            DecryptResponse response = DecryptResponse.newBuilder()
                    .setSuccess(false)
                    .setErrorMessage(e.getMessage())
                    .build();

            responseObserver.onNext(response);
            responseObserver.onCompleted();
        }
    }
}
