package uk.gov.di.ipv.stub.core.config.credentialissuer;

import java.net.URI;
import java.util.Map;

public class CredentialIssuerMapper {

    public CredentialIssuer map(Map<String, Object> map) {
        String id = (String) map.get("id");
        String name = (String) map.get("name");
        URI authorizeUrl = URI.create((String) map.get("authorizeUrl"));
        URI tokenUrl = URI.create((String) map.get("tokenUrl"));
        URI credentialUrl = URI.create((String) map.get("credentialUrl"));
        boolean sendIdentityClaims = Boolean.TRUE.equals(map.get("sendIdentityClaims"));
        return new CredentialIssuer(id, name, authorizeUrl, tokenUrl, credentialUrl, sendIdentityClaims);
    }

}