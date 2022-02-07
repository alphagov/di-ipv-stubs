package uk.gov.di.ipv.stub.core.config;

import com.google.gson.Gson;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.yaml.snakeyaml.Yaml;
import uk.gov.di.ipv.stub.core.config.credentialissuer.CredentialIssuer;
import uk.gov.di.ipv.stub.core.config.credentialissuer.CredentialIssuerMapper;
import uk.gov.di.ipv.stub.core.config.uatuser.Identity;
import uk.gov.di.ipv.stub.core.config.uatuser.IdentityMapper;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class CoreStubConfig {
    public static final String CORE_STUB_PORT = getConfigValue("CORE_STUB_PORT", "8085");
    public static final String CORE_STUB_CLIENT_ID = getConfigValue("CORE_STUB_CLIENT_ID", "ipv-core-stub");
    public static final URI CORE_STUB_REDIRECT_URL = URI.create(getConfigValue("CORE_STUB_REDIRECT_URL", "http://localhost:" + CORE_STUB_PORT + "/callback"));
    public static final int CORE_STUB_MAX_SEARCH_RESULTS = Integer.parseInt(getConfigValue("CORE_STUB_MAX_SEARCH_RESULTS", "200"));
    public static final String CORE_STUB_USER_DATA_PATH = getConfigValue("CORE_STUB_USER_DATA_PATH", "/app/config/experian-uat-users-large.zip");
    public static final String CORE_STUB_CONFIG_BASE64 = getConfigValue("CORE_STUB_CONFIG_BASE64", null);
    public static final byte[] CORE_STUB_KEYSTORE_BASE64 = getConfigValue("CORE_STUB_KEYSTORE_BASE64", null).getBytes();
    public static final String CORE_STUB_KEYSTORE_PASSWORD = getConfigValue("CORE_STUB_KEYSTORE_PASSWORD", null);
    public static final String CORE_STUB_KEYSTORE_ALIAS = getConfigValue("CORE_STUB_KEYSTORE_ALIAS", null);

    public static final List<Identity> identities = new ArrayList<>();
    public static final List<CredentialIssuer> credentialIssuers = new ArrayList<>();

    private static String getConfigValue(String key, String defaultValue) {
        String envValue = Optional.ofNullable(System.getenv(key)).orElse(defaultValue);
        if (StringUtils.isBlank(envValue)) {
            throw new IllegalStateException("env var '%s' is not set and there is no default value".formatted(key));
        }
        return envValue;
    }

    public static void initCRIS() throws IOException {
        byte[] decode = Base64.getDecoder().decode(CoreStubConfig.CORE_STUB_CONFIG_BASE64);
        Map<String, Object> obj = new Yaml().load(new ByteArrayInputStream(decode));
        CredentialIssuerMapper mapper = new CredentialIssuerMapper();
        List<Map> cis = (List<Map>) obj.get("credentialIssuerConfigs");
        credentialIssuers.addAll(cis.stream().map(mapper::map).collect(Collectors.toList()));

    }

    public static void initUATUsers() throws IOException {
        Path path = Paths.get(CoreStubConfig.CORE_STUB_USER_DATA_PATH);
        try (InputStream is = Files.newInputStream(path)) {
            readZip(is, (entry, zis) -> {
                if (entry.getName().endsWith(".json")) {
                    Map map = new Gson().fromJson(new InputStreamReader(zis), Map.class);
                    List people = (List) map.get("people");
                    IdentityMapper identityMapper = new IdentityMapper();
                    int rowNumber = 3; // starting row number in experian uat user sheet
                    for (Object person : people) {
                        Map personMap = (Map) person;
                        identities.add(identityMapper.map(personMap, rowNumber++));
                    }
                }
            });
        }
    }

    private static void readZip(InputStream is, BiConsumer<ZipEntry, InputStream> consumer) throws IOException {
        try (ZipInputStream zipFile = new ZipInputStream(is)) {
            ZipEntry entry;
            while ((entry = zipFile.getNextEntry()) != null) {
                consumer.accept(entry, new FilterInputStream(zipFile) {
                    @Override
                    public void close() throws IOException {
                        zipFile.closeEntry();
                    }
                });
            }
        }
    }

}