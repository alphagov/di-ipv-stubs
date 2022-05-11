package uk.gov.di.ipv.stub.cred.handlers;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.QueryParamsMap;
import spark.Request;
import spark.Response;
import spark.Route;
import uk.gov.di.ipv.stub.cred.auth.ClientJwtVerifier;
import uk.gov.di.ipv.stub.cred.config.ClientConfig;
import uk.gov.di.ipv.stub.cred.config.CredentialIssuerConfig;
import uk.gov.di.ipv.stub.cred.error.ClientAuthenticationException;
import uk.gov.di.ipv.stub.cred.service.AuthCodeService;
import uk.gov.di.ipv.stub.cred.service.TokenService;
import uk.gov.di.ipv.stub.cred.validation.ValidationResult;
import uk.gov.di.ipv.stub.cred.validation.Validator;

import javax.servlet.http.HttpServletResponse;

public class TokenHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenHandler.class);
    private static final String RESPONSE_TYPE = "application/json;charset=UTF-8";
    private static final String AUTHENTICATION_METHOD = "authenticationMethod";
    private static final String NONE_AUTHENTICATION_METHOD = "none";

    private TokenService tokenService;
    private AuthCodeService authCodeService;
    private Validator validator;
    private ClientJwtVerifier clientJwtVerifier;

    public TokenHandler(
            AuthCodeService authCodeService,
            TokenService tokenService,
            Validator validator,
            ClientJwtVerifier clientJwtVerifier) {
        this.authCodeService = authCodeService;
        this.tokenService = tokenService;
        this.validator = validator;
        this.clientJwtVerifier = clientJwtVerifier;
    }

    public Route issueAccessToken =
            (Request request, Response response) -> {
                QueryParamsMap requestParams = request.queryMap();
                response.type(RESPONSE_TYPE);

                ValidationResult validationResult = validator.validateTokenRequest(requestParams);
                if (!validationResult.isValid()) {
                    TokenErrorResponse errorResponse =
                            new TokenErrorResponse(validationResult.getError());
                    response.status(validationResult.getError().getHTTPStatusCode());

                    return errorResponse.toJSONObject().toJSONString();
                }

                if (Validator.isNullBlankOrEmpty(
                        requestParams.value(RequestParamConstants.CLIENT_ID))) {
                    try {
                        clientJwtVerifier.authenticateClient(requestParams);
                    } catch (ClientAuthenticationException e) {
                        LOGGER.error("Failed client JWT authentication: %s", e);
                        TokenErrorResponse errorResponse =
                                new TokenErrorResponse(OAuth2Error.INVALID_CLIENT);
                        response.status(OAuth2Error.INVALID_CLIENT.getHTTPStatusCode());

                        return errorResponse.toJSONObject().toJSONString();
                    }

                } else {
                    ClientConfig clientConfig =
                            CredentialIssuerConfig.getClientConfig(
                                    requestParams.value(RequestParamConstants.CLIENT_ID));
                    String authMethod =
                            clientConfig.getJwtAuthentication().get(AUTHENTICATION_METHOD);
                    if (!authMethod.equals(NONE_AUTHENTICATION_METHOD)) {
                        LOGGER.error("Invalid Auth Method: {}", authMethod);
                        TokenErrorResponse errorResponse =
                                new TokenErrorResponse(OAuth2Error.INVALID_REQUEST);
                        response.status(OAuth2Error.INVALID_REQUEST.getHTTPStatusCode());
                        return errorResponse.toJSONObject().toJSONString();
                    }
                }

                String code = requestParams.value(RequestParamConstants.AUTH_CODE);
                var redirectValidationResult =
                        validator.validateRedirectUrlsMatch(
                                authCodeService.getRedirectUrl(code),
                                requestParams.value(RequestParamConstants.REDIRECT_URI));

                if (!redirectValidationResult.isValid()) {
                    TokenErrorResponse errorResponse =
                            new TokenErrorResponse(redirectValidationResult.getError());
                    response.status(redirectValidationResult.getError().getHTTPStatusCode());

                    return errorResponse.toJSONObject().toJSONString();
                }

                AccessToken accessToken = tokenService.createBearerAccessToken();
                AccessTokenResponse tokenResponse =
                        new AccessTokenResponse(new Tokens(accessToken, new RefreshToken()));

                String payloadAssociatedWithCode = authCodeService.getPayload(code);
                authCodeService.revoke(code);
                tokenService.persist(accessToken, payloadAssociatedWithCode);

                response.status(HttpServletResponse.SC_OK);
                return tokenResponse.toJSONObject().toJSONString();
            };
}
