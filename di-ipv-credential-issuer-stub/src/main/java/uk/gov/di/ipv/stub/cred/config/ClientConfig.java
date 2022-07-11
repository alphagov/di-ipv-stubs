package uk.gov.di.ipv.stub.cred.config;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

public class ClientConfig {
    private String signingPublicJwk;
    private Map<String, String> jwtAuthentication;
    private String base64EncryptionPrivateKey;
    private String audienceForVcJwt;
    private String encryptionPublicJwk;

    public String getSigningPublicJwk() {
        return signingPublicJwk;
    }

    public String getEncryptionPublicJwk() {
        return encryptionPublicJwk;
    }

    public void setSigningPublicJwk(String signingPublicJwk) {
        this.signingPublicJwk = signingPublicJwk;
    }

    public Map<String, String> getJwtAuthentication() {
        return jwtAuthentication;
    }

    public void setJwtAuthentication(Map<String, String> jwtAuthentication) {
        this.jwtAuthentication = jwtAuthentication;
    }

    public PrivateKey getEncryptionPrivateKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] binaryKey = Base64.getDecoder().decode(base64EncryptionPrivateKey);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(binaryKey);
        return factory.generatePrivate(privateKeySpec);
    }

    public void setEncryptionPrivateKey(String encryptionPrivateKey) {
        this.base64EncryptionPrivateKey = base64EncryptionPrivateKey;
    }

    public String getAudienceForVcJwt() {
        return audienceForVcJwt;
    }

    public void setAudienceForVcJwt(String audienceForVcJwt) {
        this.audienceForVcJwt = audienceForVcJwt;
    }
}
