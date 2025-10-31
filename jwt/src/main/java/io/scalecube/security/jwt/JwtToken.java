package io.scalecube.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

public record JwtToken(Map<String, Object> header, Map<String, Object> payload) {

  /**
   * Parses given JWT without verifying its signature.
   *
   * @param token jwt token
   * @return parsed token
   */
  public static JwtToken parseToken(String token) {
    String[] parts = token.split("\\.");
    if (parts.length != 3) {
      throw new JwtTokenException("Invalid JWT format");
    }

    try {
      final var urlDecoder = Base64.getUrlDecoder();
      final var headerJson = new String(urlDecoder.decode(parts[0]), StandardCharsets.UTF_8);
      final var payloadJson = new String(urlDecoder.decode(parts[1]), StandardCharsets.UTF_8);

      final var mapper = new ObjectMapper();
      final var header = mapper.readValue(headerJson, Map.class);
      final var claims = mapper.readValue(payloadJson, Map.class);

      //noinspection unchecked
      return new JwtToken(header, claims);
    } catch (IOException e) {
      throw new JwtTokenException("Failed to decode JWT", e);
    }
  }
}
