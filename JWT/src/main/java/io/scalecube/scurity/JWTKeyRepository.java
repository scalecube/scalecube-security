package io.scalecube.scurity;

import java.util.Optional;

/**
 *  Retrieve corresponding JWT key that will be used in authenticate phase
 *  RSA\EC should be provider in XXXXX encoding
 *  HMAC should be provided in XXXX(UTF-8) encoding
 *
 */
public interface JWTKeyRepository {
    //TODO: check
    Optional<byte[]> getKey(String keyId);

}


