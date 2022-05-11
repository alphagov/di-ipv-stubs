package uk.gov.di.ipv.stub.cred.validation;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.QueryParamsMap;
import uk.gov.di.ipv.stub.cred.config.ClientConfig;
import uk.gov.di.ipv.stub.cred.config.CredentialIssuerConfig;
import uk.gov.di.ipv.stub.cred.config.CriType;
import uk.gov.di.ipv.stub.cred.handlers.RequestParamConstants;
import uk.gov.di.ipv.stub.cred.service.AuthCodeService;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class Validator {

    private static final Logger LOGGER = LoggerFactory.getLogger(Validator.class);
    private static final String PAAS_DOMAIN = ".london.cloudapps.digital";
    private static final String INVALID_GPG45_SCORE_ERROR_CODE = "1001";
    private static final String INVALID_EVIDENCE_VALUES_ERROR_CODE = "1002";
    private static final String INVALID_ACTIVITY_VALUES_ERROR_CODE = "1003";
    private static final String INVALID_FRAUD_VALUES_ERROR_CODE = "1004";
    private static final String INVALID_VERIFICATION_VALUES_ERROR_CODE = "1005";

    private static final String REDIRECT_URI_SEPARATOR = ",";

    private final AuthCodeService authCodeService;

    public Validator(AuthCodeService authCodeService) {
        this.authCodeService = authCodeService;
    }

    public static boolean isNullBlankOrEmpty(String value) {
        return Objects.isNull(value) || value.isEmpty() || value.isBlank();
    }

    public static boolean isNullBlankOrEmpty(Object value) {
        return Objects.isNull(value) || value.toString().isEmpty() || value.toString().isBlank();
    }

    public static ValidationResult verifyGpg45(
            CriType criType,
            String strengthValue,
            String validityValue,
            String activityValue,
            String fraudValue,
            String verificationValue) {
        switch (criType) {
            case EVIDENCE_CRI_TYPE:
                try {
                    Integer.parseInt(strengthValue);
                    Integer.parseInt(validityValue);

                    return areStringsNullOrEmpty(
                            Arrays.asList(activityValue, fraudValue, verificationValue));
                } catch (NumberFormatException e) {
                    return new ValidationResult(
                            false,
                            new ErrorObject(
                                    INVALID_EVIDENCE_VALUES_ERROR_CODE,
                                    "Invalid numbers provided for evidence strength and validity"));
                }
            case ACTIVITY_CRI_TYPE:
                try {
                    Integer.parseInt(activityValue);

                    return areStringsNullOrEmpty(
                            Arrays.asList(
                                    strengthValue, validityValue, fraudValue, verificationValue));
                } catch (NumberFormatException e) {
                    return new ValidationResult(
                            false,
                            new ErrorObject(
                                    INVALID_ACTIVITY_VALUES_ERROR_CODE,
                                    "Invalid number provided for activity"));
                }
            case FRAUD_CRI_TYPE:
                try {
                    Integer.parseInt(fraudValue);

                    return areStringsNullOrEmpty(
                            Arrays.asList(
                                    strengthValue,
                                    validityValue,
                                    activityValue,
                                    verificationValue));
                } catch (NumberFormatException e) {
                    return new ValidationResult(
                            false,
                            new ErrorObject(
                                    INVALID_FRAUD_VALUES_ERROR_CODE,
                                    "Invalid number provided for fraud"));
                }
            case VERIFICATION_CRI_TYPE:
                try {
                    Integer.parseInt(verificationValue);

                    return areStringsNullOrEmpty(
                            Arrays.asList(strengthValue, validityValue, activityValue, fraudValue));
                } catch (NumberFormatException e) {
                    return new ValidationResult(
                            false,
                            new ErrorObject(
                                    INVALID_VERIFICATION_VALUES_ERROR_CODE,
                                    "Invalid number provided for verification"));
                }
            default:
                return ValidationResult.createValidResult();
        }
    }

    public static boolean redirectUrlIsInvalid(String clientId, String redirectUri) {
        ClientConfig clientConfig = CredentialIssuerConfig.getClientConfig(clientId);

        if (isRedirectUriPaasDomain(redirectUri)) {
            return false;
        }

        List<String> validRedirectUrls =
                Arrays.asList(
                        clientConfig
                                .getJwtAuthentication()
                                .get("validRedirectUrls")
                                .split(REDIRECT_URI_SEPARATOR));
        return !validRedirectUrls.contains(redirectUri);
    }

    /**
     * To simplify the configuration of the CRI stubs they will accept any redirectUri that includes
     * the London PaaS Domain. This removes the need to configure the stub with the redirect uri of
     * each of the developer environments which share the common stubs.
     *
     * <p>Keeping some redirect uri validation will still permit developers to check the behaviour
     * when required.
     *
     * @param redirectUri
     * @return true if the redirect uri includes the London PaaS Domain
     */
    private static boolean isRedirectUriPaasDomain(String redirectUri) {
        return redirectUri != null && redirectUri.contains(PAAS_DOMAIN);
    }

    public ValidationResult validateRedirectUrlsMatch(
            String redirectUrlFromAuthEndpoint, String redirectUrlFromTokenEndpoint) {
        if (Validator.isNullBlankOrEmpty(redirectUrlFromAuthEndpoint)
                && Validator.isNullBlankOrEmpty(redirectUrlFromTokenEndpoint)) {
            return ValidationResult.createValidResult();
        }

        if (Validator.isNullBlankOrEmpty(redirectUrlFromAuthEndpoint)) {
            return new ValidationResult(false, OAuth2Error.INVALID_GRANT);
        }

        if (!redirectUrlFromAuthEndpoint.equals(redirectUrlFromTokenEndpoint)) {
            return new ValidationResult(false, OAuth2Error.INVALID_GRANT);
        }

        return ValidationResult.createValidResult();
    }

    public ValidationResult validateTokenRequest(QueryParamsMap requestParams) {
        String clientIdValue = requestParams.value(RequestParamConstants.CLIENT_ID);
        String assertionType = requestParams.value(RequestParamConstants.CLIENT_ASSERTION_TYPE);
        String assertion = requestParams.value(RequestParamConstants.CLIENT_ASSERTION);

        if (Validator.isNullBlankOrEmpty(clientIdValue)
                && (Validator.isNullBlankOrEmpty(assertionType)
                        || Validator.isNullBlankOrEmpty(assertion))) {
            LOGGER.error("Missing client id or client assertion param values");
            return new ValidationResult(false, OAuth2Error.INVALID_CLIENT);
        }

        if (!Validator.isNullBlankOrEmpty(clientIdValue)
                && CredentialIssuerConfig.getClientConfig(clientIdValue) == null) {
            LOGGER.error("Failed to find config for provided client id: {}", clientIdValue);
            return new ValidationResult(false, OAuth2Error.INVALID_CLIENT);
        }

        String grantTypeValue = requestParams.value(RequestParamConstants.GRANT_TYPE);
        if (Validator.isNullBlankOrEmpty(grantTypeValue)
                || !grantTypeValue.equalsIgnoreCase(GrantType.AUTHORIZATION_CODE.getValue())) {
            return new ValidationResult(false, OAuth2Error.UNSUPPORTED_GRANT_TYPE);
        }

        String authCodeValue = requestParams.value(RequestParamConstants.AUTH_CODE);
        if (Validator.isNullBlankOrEmpty(authCodeValue)) {
            return new ValidationResult(false, OAuth2Error.INVALID_GRANT);
        }
        if (Objects.isNull(this.authCodeService.getPayload(authCodeValue))) {
            return new ValidationResult(false, OAuth2Error.INVALID_GRANT);
        }

        String redirectUriValue = requestParams.value(RequestParamConstants.REDIRECT_URI);
        if (Validator.isNullBlankOrEmpty(redirectUriValue)) {
            LOGGER.error("Invalid Redirect URI: {}", redirectUriValue);
            return new ValidationResult(false, OAuth2Error.INVALID_REQUEST);
        }

        return ValidationResult.createValidResult();
    }

    private static ValidationResult areStringsNullOrEmpty(List<String> values) {
        for (String value : values) {
            if (!isNullBlankOrEmpty(value)) {
                return new ValidationResult(
                        false,
                        new ErrorObject(
                                INVALID_GPG45_SCORE_ERROR_CODE, "Invalid GPG45 score provided"));
            }
        }
        return ValidationResult.createValidResult();
    }
}
