package uk.gov.di.ipv.stub.core.config.credentialissuer;

import java.net.URI;

public record CredentialIssuer(
        String id,
        String name,
        URI authorizeUrl,
        URI tokenUrl,
        URI credentialUrl,
        URI audience,
        boolean sendIdentityClaims,
        String expectedAlgo,
        String publicEncryptionJwkBase64,
        String apiKeyEnvVar) {}
