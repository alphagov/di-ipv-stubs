package uk.gov.di.ipv.stub.cred.handlers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.MapUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.QueryParamsMap;
import spark.Request;
import spark.Response;
import spark.Route;
import uk.gov.di.ipv.stub.cred.config.ClientConfig;
import uk.gov.di.ipv.stub.cred.config.CredentialIssuerConfig;
import uk.gov.di.ipv.stub.cred.config.CriType;
import uk.gov.di.ipv.stub.cred.domain.Credential;
import uk.gov.di.ipv.stub.cred.error.CriStubException;
import uk.gov.di.ipv.stub.cred.service.AuthCodeService;
import uk.gov.di.ipv.stub.cred.service.CredentialService;
import uk.gov.di.ipv.stub.cred.utils.ES256SignatureVerifier;
import uk.gov.di.ipv.stub.cred.utils.ViewHelper;
import uk.gov.di.ipv.stub.cred.validation.ValidationResult;
import uk.gov.di.ipv.stub.cred.validation.Validator;

import javax.servlet.http.HttpServletResponse;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public class AuthorizeHandler {

    public static final String SHARED_CLAIMS = "shared_claims";

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizeHandler.class);

    private static final String DEFAULT_RESPONSE_CONTENT_TYPE = "application/x-www-form-urlencoded";
    private static final String ERROR_CODE_INVALID_REQUEST_JWT = "invalid_request_jwt";

    private static final String RESOURCE_ID_PARAM = "resourceId";
    private static final String JSON_PAYLOAD_PARAM = "jsonPayload";
    private static final String IS_EVIDENCE_TYPE_PARAM = "isEvidenceType";
    private static final String IS_ACTIVITY_TYPE_PARAM = "isActivityType";
    private static final String IS_FRAUD_TYPE_PARAM = "isFraudType";
    private static final String IS_VERIFICATION_TYPE_PARAM = "isVerificationType";
    private static final String HAS_ERROR_PARAM = "hasError";
    private static final String ERROR_PARAM = "error";
    private static final String CRI_NAME_PARAM = "cri-name";

    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private final AuthCodeService authCodeService;
    private final CredentialService credentialService;
    private final ES256SignatureVerifier es256SignatureVerifier = new ES256SignatureVerifier();
    private ViewHelper viewHelper;

    public AuthorizeHandler(
            ViewHelper viewHelper,
            AuthCodeService authCodeService,
            CredentialService credentialService) {
        Objects.requireNonNull(viewHelper);
        this.viewHelper = viewHelper;
        this.authCodeService = authCodeService;
        this.credentialService = credentialService;
    }

    public Route doAuthorize =
            (Request request, Response response) -> {
                QueryParamsMap queryParamsMap = request.queryMap();

                ValidationResult validationResult = validateQueryParams(queryParamsMap);

                if (!validationResult.isValid()) {
                    if (validationResult
                            .getError()
                            .getCode()
                            .equals(ERROR_CODE_INVALID_REQUEST_JWT)) {
                        response.status(HttpServletResponse.SC_BAD_REQUEST);
                        return validationResult.getError().getDescription();
                    }

                    String clientIdValue = queryParamsMap.value(RequestParamConstants.CLIENT_ID);
                    String requestValue = queryParamsMap.value(RequestParamConstants.REQUEST);

                    ClientConfig clientConfig =
                            CredentialIssuerConfig.getClientConfig(clientIdValue);

                    if (clientConfig == null) {
                        response.status(HttpServletResponse.SC_BAD_REQUEST);
                        return "Error: Could not find client configuration details for: "
                                + clientIdValue;
                    }

                    SignedJWT signedJWT =
                            getSignedJWT(requestValue, clientConfig.getEncryptionPrivateKey());

                    AuthorizationErrorResponse errorResponse =
                            new AuthorizationErrorResponse(
                                    URI.create(
                                            signedJWT
                                                    .getJWTClaimsSet()
                                                    .getClaim(RequestParamConstants.REDIRECT_URI)
                                                    .toString()),
                                    validationResult.getError(),
                                    State.parse(
                                            signedJWT
                                                    .getJWTClaimsSet()
                                                    .getClaim(RequestParamConstants.STATE)
                                                    .toString()),
                                    ResponseMode.QUERY);

                    response.type(DEFAULT_RESPONSE_CONTENT_TYPE);
                    response.redirect(errorResponse.toURI().toString());
                    // No content required in response
                    return null;
                }

//                String sharedClaimsJson = getSharedAttributes(queryParamsMap);

                CriType criType = CredentialIssuerConfig.getCriType();

                Map<String, Object> frontendParams = new HashMap<>();
                frontendParams.put(RESOURCE_ID_PARAM, UUID.randomUUID().toString());
                frontendParams.put(
                        IS_EVIDENCE_TYPE_PARAM, criType.equals(CriType.EVIDENCE_CRI_TYPE));
                frontendParams.put(
                        IS_ACTIVITY_TYPE_PARAM, criType.equals(CriType.ACTIVITY_CRI_TYPE));
                frontendParams.put(IS_FRAUD_TYPE_PARAM, criType.equals(CriType.FRAUD_CRI_TYPE));
                frontendParams.put(
                        IS_VERIFICATION_TYPE_PARAM, criType.equals(CriType.VERIFICATION_CRI_TYPE));
//                frontendParams.put(SHARED_CLAIMS, sharedClaimsJson);

                String error = request.attribute(ERROR_PARAM);
                boolean hasError = error != null;
                frontendParams.put(HAS_ERROR_PARAM, hasError);
                if (hasError) {
                    frontendParams.put(ERROR_PARAM, error);
                }

                frontendParams.put(CRI_NAME_PARAM, CredentialIssuerConfig.NAME);

                return viewHelper.render(frontendParams, "authorize.mustache");
            };

    public Route generateResponse =
            (Request request, Response response) -> {
                QueryParamsMap queryParamsMap = request.queryMap();

                String clientIdValue = queryParamsMap.value(RequestParamConstants.CLIENT_ID);
                String requestValue = queryParamsMap.value(RequestParamConstants.REQUEST);

                ClientConfig clientConfig = CredentialIssuerConfig.getClientConfig(clientIdValue);

                if (clientConfig == null) {
                    response.status(HttpServletResponse.SC_BAD_REQUEST);
                    return "Error: Could not find client configuration details for: "
                            + clientIdValue;
                }

                SignedJWT signedJWT =
                        getSignedJWT(requestValue, clientConfig.getEncryptionPrivateKey());
                String redirectUri =
                        signedJWT
                                .getJWTClaimsSet()
                                .getClaim(RequestParamConstants.REDIRECT_URI)
                                .toString();
                String userId = signedJWT.getJWTClaimsSet().getSubject();

                try {
                    Map<String, Object> attributesMap =
                            generateJsonPayload(queryParamsMap.value(JSON_PAYLOAD_PARAM));

//                    Map<String, Object> combinedAttributeJson =
//                            generateJsonPayload(getSharedAttributes(queryParamsMap));
//
//                    combinedAttributeJson.putAll(attributesMap);

                    Map<String, Object> gpgMap =
                            generateGpg45Score(
                                    CredentialIssuerConfig.getCriType(),
                                    queryParamsMap.value(
                                            CredentialIssuerConfig.EVIDENCE_STRENGTH_PARAM),
                                    queryParamsMap.value(
                                            CredentialIssuerConfig.EVIDENCE_VALIDITY_PARAM),
                                    queryParamsMap.value(CredentialIssuerConfig.ACTIVITY_PARAM),
                                    queryParamsMap.value(CredentialIssuerConfig.FRAUD_PARAM),
                                    queryParamsMap.value(
                                            CredentialIssuerConfig.VERIFICATION_PARAM));

                    Credential credential = new Credential(attributesMap, gpgMap, userId);

                    AuthorizationSuccessResponse successResponse =
                            generateAuthCode(
                                    signedJWT
                                            .getJWTClaimsSet()
                                            .getClaim(RequestParamConstants.STATE)
                                            .toString(),
                                    redirectUri);
                    persistData(
                            queryParamsMap,
                            successResponse.getAuthorizationCode(),
                            credential,
                            redirectUri);

                    response.type(DEFAULT_RESPONSE_CONTENT_TYPE);
                    response.redirect(successResponse.toURI().toString());
                } catch (CriStubException e) {
                    AuthorizationErrorResponse errorResponse =
                            generateErrorResponse(e, redirectUri);
                    response.redirect(errorResponse.toURI().toString());
                }
                return null;
            };

    private AuthorizationSuccessResponse generateAuthCode(String state, String redirectUri) {
        AuthorizationCode authorizationCode = new AuthorizationCode();

        return new AuthorizationSuccessResponse(
                URI.create(redirectUri),
                authorizationCode,
                null,
                State.parse(state),
                ResponseMode.QUERY);
    }

    private AuthorizationErrorResponse generateErrorResponse(
            CriStubException error, String redirectUri) {
        return new AuthorizationErrorResponse(
                URI.create(redirectUri),
                new ErrorObject(error.getMessage(), error.getDescription()),
                null,
                new Issuer(CredentialIssuerConfig.NAME),
                ResponseMode.QUERY);
    }

    private void persistData(
            QueryParamsMap queryParamsMap,
            AuthorizationCode authorizationCode,
            Credential credential,
            String redirectUri) {
        String resourceId = queryParamsMap.value(RequestParamConstants.RESOURCE_ID);
        this.authCodeService.persist(authorizationCode, resourceId, redirectUri);
        this.credentialService.persist(credential, resourceId);
    }

    private Map<String, Object> generateJsonPayload(String payload) throws CriStubException {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(payload, Map.class);
        } catch (JsonProcessingException e) {
            throw new CriStubException("invalid_json", "Unable to generate valid JSON Payload", e);
        }
    }

    private Map<String, Object> generateGpg45Score(
            CriType criType,
            String strengthValue,
            String validityValue,
            String activityValue,
            String fraudValue,
            String verificationValue)
            throws CriStubException {
        ValidationResult validationResult =
                Validator.verifyGpg45(
                        criType,
                        strengthValue,
                        validityValue,
                        activityValue,
                        fraudValue,
                        verificationValue);

        if (!validationResult.isValid()) {
            throw new CriStubException(
                    "invalid_request", validationResult.getError().getDescription());
        }

        Map<String, Object> gpg45Score = new HashMap<>();
        switch (criType) {
            case EVIDENCE_CRI_TYPE -> {
                gpg45Score.put(
                        CredentialIssuerConfig.EVIDENCE_STRENGTH_PARAM,
                        Integer.parseInt(strengthValue));
                gpg45Score.put(
                        CredentialIssuerConfig.EVIDENCE_VALIDITY_PARAM,
                        Integer.parseInt(validityValue));
            }
            case ACTIVITY_CRI_TYPE -> gpg45Score.put(
                    CredentialIssuerConfig.ACTIVITY_PARAM, Integer.parseInt(activityValue));
            case FRAUD_CRI_TYPE -> gpg45Score.put(
                    CredentialIssuerConfig.FRAUD_PARAM, Integer.parseInt(fraudValue));
            case VERIFICATION_CRI_TYPE -> gpg45Score.put(
                    CredentialIssuerConfig.VERIFICATION_PARAM, Integer.parseInt(verificationValue));
        }
        return gpg45Score;
    }

    private ValidationResult validateQueryParams(QueryParamsMap queryParams) {
        String clientIdValue = queryParams.value(RequestParamConstants.CLIENT_ID);
        if (Validator.isNullBlankOrEmpty(clientIdValue)
                || CredentialIssuerConfig.getClientConfig(clientIdValue) == null) {
            return new ValidationResult(false, OAuth2Error.INVALID_CLIENT);
        }

        String request = queryParams.value(RequestParamConstants.REQUEST);
        if (Validator.isNullBlankOrEmpty(request)) {
            return new ValidationResult(
                    false,
                    new ErrorObject(
                            ERROR_CODE_INVALID_REQUEST_JWT,
                            "request param must be provided",
                            HttpServletResponse.SC_BAD_REQUEST));
        }

        ValidationResult validationResult = validateRequestClaims(queryParams);
        if (validationResult != null) return validationResult;

        return ValidationResult.createValidResult();
    }

    private ValidationResult validateRequestClaims(QueryParamsMap queryParams) {
        String clientIdValue = queryParams.value(RequestParamConstants.CLIENT_ID);
        ClientConfig clientConfig = CredentialIssuerConfig.getClientConfig(clientIdValue);

        try {
            SignedJWT signedJWT =
                    getSignedJWT(
                            queryParams.value(RequestParamConstants.REQUEST),
                            clientConfig.getEncryptionPrivateKey());
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

            if (Validator.isNullBlankOrEmpty(
                            jwtClaimsSet.getClaim(RequestParamConstants.RESPONSE_TYPE))
                    || !jwtClaimsSet
                            .getClaim(RequestParamConstants.RESPONSE_TYPE)
                            .toString()
                            .equals(ResponseType.Value.CODE.getValue())) {
                return new ValidationResult(false, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE);
            }

            if (Validator.isNullBlankOrEmpty(
                    jwtClaimsSet.getClaim(RequestParamConstants.REDIRECT_URI))) {
                return new ValidationResult(
                        false,
                        new ErrorObject(
                                ERROR_CODE_INVALID_REQUEST_JWT,
                                "redirect_uri param must be provided",
                                HttpServletResponse.SC_BAD_REQUEST));
            }

            if (Validator.redirectUrlIsInvalid(
                    clientIdValue,
                    jwtClaimsSet.getClaim(RequestParamConstants.REDIRECT_URI).toString())) {
                return new ValidationResult(
                        false,
                        new ErrorObject(
                                ERROR_CODE_INVALID_REQUEST_JWT,
                                "redirect_uri param provided does not match any of the redirect_uri values configured",
                                HttpServletResponse.SC_BAD_REQUEST));
            }

            if (Validator.isNullBlankOrEmpty(jwtClaimsSet.getClaim(RequestParamConstants.ISSUER))) {
                return new ValidationResult(
                        false,
                        new ErrorObject(
                                "invalid_issuer",
                                "issuer param must be provided",
                                HttpServletResponse.SC_BAD_REQUEST));
            }

            if (Validator.isNullBlankOrEmpty(
                    jwtClaimsSet.getClaim(RequestParamConstants.AUDIENCE).toString())) {
                return new ValidationResult(
                        false,
                        new ErrorObject(
                                "invalid_issuer",
                                "issuer param must be provided",
                                HttpServletResponse.SC_BAD_REQUEST));
            }

        } catch (ParseException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            return new ValidationResult(
                    false,
                    new ErrorObject(
                            "unable_to_parse_request_jwt",
                            "unable to parse queryParams jwt into signed jwt object",
                            HttpServletResponse.SC_BAD_REQUEST));
        }
        return null;
    }

    private SignedJWT getSignedJWT(String request, PrivateKey encryptionPrivateKey)
            throws ParseException {
        try {
            JWEObject jweObject = getJweObject(request, encryptionPrivateKey);
            return jweObject.getPayload().toSignedJWT();
        } catch (ParseException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException e) {
            return SignedJWT.parse(request);
        }
    }

    private String getSharedAttributes(QueryParamsMap queryParamsMap) {
        String requestParam = queryParamsMap.value(RequestParamConstants.REQUEST);
        String clientIdParam = queryParamsMap.value(RequestParamConstants.CLIENT_ID);

        if (MapUtils.isEmpty(CredentialIssuerConfig.getClientConfigs())) {
            return "Error: Missing cri stub client configuration env variable";
        }

        ClientConfig clientConfig = CredentialIssuerConfig.getClientConfig(clientIdParam);

        if (clientConfig == null) {
            return "Error: Could not find client configuration details for: " + clientIdParam;
        }

        String sharedAttributesJson;
        if (!Validator.isNullBlankOrEmpty(requestParam)) {
            try {
                SignedJWT signedJWT =
                        getSignedJWT(requestParam, clientConfig.getEncryptionPrivateKey());

                if (!es256SignatureVerifier.valid(signedJWT, clientConfig.getSigningPublicJwk())) {
                    LOGGER.error("JWT signature is invalid");
                    return "Error: Signature of the shared attribute JWT is not valid";
                }

                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
                Map<String, Object> sharedClaims = claimsSet.getJSONObjectClaim(SHARED_CLAIMS);

                if (sharedClaims == null) {
                    LOGGER.error("shared_claims not found in JWT");
                    return "Error: shared_claims not found in JWT";
                }

                sharedAttributesJson = gson.toJson(sharedClaims);
            } catch (ParseException e) {
                LOGGER.error("Failed to parse something: {}", e.getMessage());
                sharedAttributesJson =
                        String.format("Error: failed to parse something: %s", e.getMessage());
            } catch (JOSEException e) {
                LOGGER.error("Failed to verify the signature of the JWT", e);
                sharedAttributesJson =
                        "Error: failed to verify the signature of the shared attribute JWT";
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                LOGGER.error("Failed to decrypt the JWT", e);
                sharedAttributesJson = "Error: Failed to decrypt the JWT";
            }
        } else {
            sharedAttributesJson = "Error: missing 'request' query parameter";
        }
        return sharedAttributesJson;
    }

    private JWEObject getJweObject(String requestParam, PrivateKey encryptionPrivateKey)
            throws ParseException, NoSuchAlgorithmException, InvalidKeySpecException,
                    JOSEException {
        JWEObject encryptedJweObject = JWEObject.parse(requestParam);
        RSADecrypter rsaDecrypter = new RSADecrypter(encryptionPrivateKey);
        encryptedJweObject.decrypt(rsaDecrypter);
        return encryptedJweObject;
    }
}
