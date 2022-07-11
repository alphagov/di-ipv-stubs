package uk.gov.di.ipv.stub.cred.config;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CredentialIssuerConfig {
    public static final String PORT = getConfigValue("CREDENTIAL_ISSUER_PORT", "8084");
    public static final String NAME =
            getConfigValue("CREDENTIAL_ISSUER_NAME", "Credential Issuer Stub");
    public static final String VC_DEFAULT_TTL = "300";

    public static String CLIENT_AUDIENCE = getConfigValue("CLIENT_AUDIENCE", null);

    public static final String EVIDENCE_STRENGTH_PARAM = "strength";
    public static final String EVIDENCE_VALIDITY_PARAM = "validity";
    public static final String ACTIVITY_PARAM = "activity";
    public static final String FRAUD_PARAM = "fraud";
    public static final String VERIFICATION_PARAM = "verification";

    public static Map<String, ClientConfig> CLIENT_CONFIGS;

    private static final Gson gson = new Gson();
    private static final String CREDENTIAL_ISSUER_TYPE_VAR = "CREDENTIAL_ISSUER_TYPE";

    private CredentialIssuerConfig() {}

    public static CriType getCriType() {
        return CriType.fromValue(
                getConfigValue(CREDENTIAL_ISSUER_TYPE_VAR, CriType.EVIDENCE_CRI_TYPE.value));
    }

    public static ClientConfig getClientConfig(String clientId) {
        if (CLIENT_CONFIGS == null) {
            CLIENT_CONFIGS = parseClientConfigs();
        }
        return CLIENT_CONFIGS.get(clientId);
    }

    public static ClientConfig getDocAppClientConfig() {
        return getClientConfig("authOrchestratorDocApp");
    }

    public static Map<String, ClientConfig> getClientConfigs() {
        if (CLIENT_CONFIGS == null) {
            CLIENT_CONFIGS = parseClientConfigs();
        }
        return CLIENT_CONFIGS;
    }

    public static void resetClientConfigs() {
        // For testing purposes only.
        CLIENT_CONFIGS = null;
        CLIENT_AUDIENCE = getConfigValue("CLIENT_AUDIENCE", null);
    }

    public static String getVerifiableCredentialIssuer() {
        return getConfigValue("VC_ISSUER", null);
    }

    public static String getVerifiableCredentialSigningKey() {
        return getConfigValue("VC_SIGNING_KEY", null);
    }

    public static Long getVerifiableCredentialTtlSeconds() {
        return Long.parseLong(getConfigValue("VC_TTL_SECONDS", VC_DEFAULT_TTL));
    }

    private static String getConfigValue(String key, String defaultValue) {
        var envValue = System.getenv(key);
        if (envValue == null) {
            return defaultValue;
        }

        return envValue;
    }

    private static Map<String, ClientConfig> parseClientConfigs() {
        String client_config = getConfigValue("CLIENT_CONFIG", null);
        if (client_config == null) {
            return new HashMap<>();
        }

        String clientConfigJson = new String(Base64.getDecoder().decode(client_config));
        Type type = new TypeToken<Map<String, ClientConfig>>() {}.getType();

        return gson.fromJson(clientConfigJson, type);
    }
}
