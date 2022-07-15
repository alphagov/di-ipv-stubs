package uk.gov.di.ipv.stub.cred.handlers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.eclipse.jetty.http.HttpHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.Request;
import spark.Response;
import spark.Route;
import uk.gov.di.ipv.stub.cred.domain.Credential;
import uk.gov.di.ipv.stub.cred.service.CredentialService;
import uk.gov.di.ipv.stub.cred.service.TokenService;
import uk.gov.di.ipv.stub.cred.validation.ValidationResult;
import uk.gov.di.ipv.stub.cred.validation.Validator;
import uk.gov.di.ipv.stub.cred.vc.VerifiableCredentialGenerator;

import javax.servlet.http.HttpServletResponse;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public class CredentialHandler {

    private static final String RESPONSE_TYPE = "application/json;charset=UTF-8";
    private static final String DEFAULT_RESPONSE_CONTENT_TYPE = "application/jwt;charset=UTF-8";
    private static final Logger LOGGER = LoggerFactory.getLogger(CredentialHandler.class);


    private CredentialService credentialService;
    private TokenService tokenService;
    private VerifiableCredentialGenerator verifiableCredentialGenerator;

    public CredentialHandler(
            CredentialService credentialService,
            TokenService tokenService,
            VerifiableCredentialGenerator verifiableCredentialGenerator) {
        this.credentialService = credentialService;
        this.tokenService = tokenService;
        this.verifiableCredentialGenerator = verifiableCredentialGenerator;
    }

    public Route getResource =
            (Request request, Response response) -> {
                String accessTokenString = request.headers(HttpHeader.AUTHORIZATION.toString());

                ValidationResult validationResult = validateAccessToken(accessTokenString);

                if (!validationResult.isValid()) {
                    response.status(validationResult.getError().getHTTPStatusCode());
                    return validationResult.getError().getDescription();
                }

//                if (Validator.isNullBlankOrEmpty(request.body())) {
//                    response.status(HttpServletResponse.SC_BAD_REQUEST);
//                    return "Error: No body found in request";
//                }
                String verifiableCredential;
                try {
                    String resourceId = tokenService.getPayload(accessTokenString);
                    Credential credential = credentialService.getCredential(resourceId);


                    verifiableCredential =
                            verifiableCredentialGenerator.generate(credential).serialize();
                } catch (Exception e) {
                    LOGGER.error("Exception: ", e);
                    response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    return String.format("Error: Unable to generate VC - '%s'", e.getMessage());
                }

                tokenService.revoke(accessTokenString);

                response.type(RESPONSE_TYPE);
                response.status(HttpServletResponse.SC_CREATED);

                var userInfo = new UserInfo(new Subject("urn:fdc:gov.uk:2022:"+UUID.randomUUID()));
                userInfo.setClaim("https://vocab.account.gov.uk/v1/credentialJWT", List.of(verifiableCredential));

                return userInfo.toJSONString();
            };

    private ValidationResult validateAccessToken(String accessTokenString) {
        if (Validator.isNullBlankOrEmpty(accessTokenString)) {
            return new ValidationResult(false, OAuth2Error.INVALID_REQUEST);
        }

        if (Objects.isNull(this.tokenService.getPayload(accessTokenString))) {
            return new ValidationResult(false, OAuth2Error.INVALID_CLIENT);
        }

        try {
            AccessToken.parse(accessTokenString);
        } catch (ParseException e) {
            return new ValidationResult(false, OAuth2Error.INVALID_REQUEST);
        }

        return ValidationResult.createValidResult();
    }
}
