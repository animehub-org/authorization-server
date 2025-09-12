# Anime Auth API

Authorization API for anime hub.
**This project is an example, the real implementation is on [UserApi](https://github.com/animehub-org/user-api)**.

## Endpoints

- `/login`
  - Requirements:
    ```json
    {
      "encryptedInfo": "string",
      "recaptchaToken": "string"
    }
    ```
  - EncryptedInfo:
    ```json
    {
      "email": "string",
      "username": "string",
      "password": "string",
      "fingerprint": "string"
    }
    ```
  - Returns:
    ```json
    {
      "accessToken": "string",
      "refreshToken": "string",
      "expiresIn": "long"   
    }
    ```

The encrypted info is encrypted with RSA public key

- `/keys/public-keys`
    - Returns: RSA public key. The key is created at the startup of the server