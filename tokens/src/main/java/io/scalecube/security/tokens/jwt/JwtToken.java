package io.scalecube.security.tokens.jwt;

import java.util.Map;

public record JwtToken(Map<String, Object> header, Map<String, Object> payload) {}
