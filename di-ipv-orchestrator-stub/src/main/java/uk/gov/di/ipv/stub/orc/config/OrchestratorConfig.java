package uk.gov.di.ipv.stub.orc.config;

public class OrchestratorConfig {
    public static final String PORT = getConfigValue("ORCHESTRATOR_PORT","8083");
    public static final String IPV_CLIENT_ID = getConfigValue("IPV_CLIENT_ID", "some-client-id");
    public static final String IPV_ENDPOINT = getConfigValue("IPV_ENDPOINT", "https://di-ipv-core-front.london.cloudapps.digital/");
    public static final String IPV_BACKCHANNEL_ENDPOINT = getConfigValue("IPV_BACKCHANNEL_ENDPOINT", "https://ea8lfzcdq0.execute-api.eu-west-2.amazonaws.com/");
    public static final String IPV_BACKCHANNEL_TOKEN_PATH = getConfigValue("IPV_BACKCHANNEL_TOKEN_PATH", "/dev/token");
    public static final String IPV_BACKCHANNEL_USER_IDENTITY_PATH = getConfigValue("IPV_BACKCHANNEL_USER_IDENTITY_PATH", "/dev/user-identity");
    public static final String ORCHESTRATOR_REDIRECT_URL = getConfigValue("ORCHESTRATOR_REDIRECT_URL", "http://localhost:8083/callback");


    private static String getConfigValue(String key, String defaultValue){
        var envValue = System.getenv(key);
        if(envValue == null){
            return defaultValue;
        }

        return envValue;
    }
}
