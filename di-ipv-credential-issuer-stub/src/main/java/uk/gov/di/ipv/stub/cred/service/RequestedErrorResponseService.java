package uk.gov.di.ipv.stub.cred.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import spark.QueryParamsMap;
import uk.gov.di.ipv.stub.cred.config.ClientConfig;
import uk.gov.di.ipv.stub.cred.config.CredentialIssuerConfig;
import uk.gov.di.ipv.stub.cred.handlers.RequestParamConstants;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RequestedErrorResponseService {
    public static final String AUTH = "auth";
    public static final String TOKEN = "token";
    public static final String NONE = "none";

    private final Map<String, Map<String, String>> errorResponsesRequested;

    public RequestedErrorResponseService() {
        this.errorResponsesRequested = new ConcurrentHashMap<>();
    }

    public void persist(String authCode, QueryParamsMap queryParamsMap) {
        Map<String, String> parmsValuesMap = new HashMap<>();
        parmsValuesMap.put(
                RequestParamConstants.REQUESTED_OAUTH_ERROR,
                queryParamsMap.value(RequestParamConstants.REQUESTED_OAUTH_ERROR));
        parmsValuesMap.put(
                RequestParamConstants.REQUESTED_OAUTH_ERROR_ENDPOINT,
                queryParamsMap.value(RequestParamConstants.REQUESTED_OAUTH_ERROR_ENDPOINT));
        parmsValuesMap.put(
                RequestParamConstants.REQUESTED_OAUTH_ERROR_DESCRIPTION,
                queryParamsMap.value(RequestParamConstants.REQUESTED_OAUTH_ERROR_DESCRIPTION));

        errorResponsesRequested.put(authCode, parmsValuesMap);
    }

    public AuthorizationErrorResponse getRequestedAuthErrorResponse(QueryParamsMap queryParamsMap)
            throws NoSuchAlgorithmException, InvalidKeySpecException, ParseException {
        String endpoint =
                queryParamsMap.value(RequestParamConstants.REQUESTED_OAUTH_ERROR_ENDPOINT);
        String error = queryParamsMap.value(RequestParamConstants.REQUESTED_OAUTH_ERROR);
        String description =
                queryParamsMap.value(RequestParamConstants.REQUESTED_OAUTH_ERROR_DESCRIPTION);

        if (AUTH.equals(endpoint) && !NONE.equals(error)) {
            String clientIdValue = queryParamsMap.value(RequestParamConstants.CLIENT_ID);
            ClientConfig clientConfig = CredentialIssuerConfig.getClientConfig(clientIdValue);

            String redirectUri =
                    getSignedJWT(
                                    queryParamsMap.value(RequestParamConstants.REQUEST),
                                    clientConfig.getEncryptionPrivateKey())
                            .getJWTClaimsSet()
                            .getClaim(RequestParamConstants.REDIRECT_URI)
                            .toString();

            String state = queryParamsMap.value(RequestParamConstants.STATE);

            return new AuthorizationErrorResponse(
                    URI.create(redirectUri),
                    new ErrorObject(error, description),
                    (state == null || state.isEmpty()) ? null : new State(state),
                    new Issuer(CredentialIssuerConfig.NAME),
                    ResponseMode.QUERY);
        }
        return null;
    }

    public TokenErrorResponse getRequestedAccessTokenErrorResponse(String authCode) {
        Map<String, String> requestedErrorResponse = errorResponsesRequested.get(authCode);
        if (requestedErrorResponse != null) {
            String error = requestedErrorResponse.get(RequestParamConstants.REQUESTED_OAUTH_ERROR);
            String endpoint =
                    requestedErrorResponse.get(
                            RequestParamConstants.REQUESTED_OAUTH_ERROR_ENDPOINT);

            if ((TOKEN.equals(endpoint)) && (!NONE.equals(error))) {
                return new TokenErrorResponse(
                        new ErrorObject(
                                error,
                                requestedErrorResponse.get(
                                        RequestParamConstants.REQUESTED_OAUTH_ERROR_DESCRIPTION)));
            }
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

    private JWEObject getJweObject(String requestParam, PrivateKey encryptionPrivateKey)
            throws ParseException, NoSuchAlgorithmException, InvalidKeySpecException,
                    JOSEException {
        JWEObject encryptedJweObject = JWEObject.parse(requestParam);
        RSADecrypter rsaDecrypter = new RSADecrypter(encryptionPrivateKey);
        encryptedJweObject.decrypt(rsaDecrypter);
        return encryptedJweObject;
    }
}
