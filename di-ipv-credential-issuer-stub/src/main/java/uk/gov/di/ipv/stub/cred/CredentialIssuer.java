package uk.gov.di.ipv.stub.cred;

import spark.Spark;
import uk.gov.di.ipv.stub.cred.auth.ClientJwtVerifier;
import uk.gov.di.ipv.stub.cred.config.CredentialIssuerConfig;
import uk.gov.di.ipv.stub.cred.handlers.AuthorizeHandler;
import uk.gov.di.ipv.stub.cred.handlers.CredentialHandler;
import uk.gov.di.ipv.stub.cred.handlers.JwksHandler;
import uk.gov.di.ipv.stub.cred.handlers.TokenHandler;
import uk.gov.di.ipv.stub.cred.service.AuthCodeService;
import uk.gov.di.ipv.stub.cred.service.CredentialService;
import uk.gov.di.ipv.stub.cred.service.RequestedErrorResponseService;
import uk.gov.di.ipv.stub.cred.service.TokenService;
import uk.gov.di.ipv.stub.cred.utils.ViewHelper;
import uk.gov.di.ipv.stub.cred.validation.Validator;
import uk.gov.di.ipv.stub.cred.vc.VerifiableCredentialGenerator;

public class CredentialIssuer {

    private final AuthorizeHandler authorizeHandler;
    private final TokenHandler tokenHandler;
    private final CredentialHandler credentialHandler;
    private final JwksHandler jwksHandler;

    public CredentialIssuer() {
        Spark.staticFileLocation("/public");
        Spark.port(Integer.parseInt(CredentialIssuerConfig.PORT));

        AuthCodeService authCodeService = new AuthCodeService();
        TokenService tokenService = new TokenService();
        Validator validator = new Validator(authCodeService);
        ClientJwtVerifier clientJwtVerifier = new ClientJwtVerifier();
        CredentialService credentialService = new CredentialService();
        VerifiableCredentialGenerator vcGenerator = new VerifiableCredentialGenerator();
        RequestedErrorResponseService requestedErrorResponseService =
                new RequestedErrorResponseService();

        authorizeHandler =
                new AuthorizeHandler(
                        new ViewHelper(),
                        authCodeService,
                        credentialService,
                        requestedErrorResponseService);
        tokenHandler =
                new TokenHandler(
                        authCodeService,
                        tokenService,
                        validator,
                        clientJwtVerifier,
                        requestedErrorResponseService);
        credentialHandler = new CredentialHandler(credentialService, tokenService, vcGenerator);
        jwksHandler = new JwksHandler();

        initRoutes();
        initErrorMapping();
    }

    private void initRoutes() {
        Spark.get("/authorize", authorizeHandler.doAuthorize);
        Spark.post("/authorize", authorizeHandler.generateResponse);
        Spark.post("/token", tokenHandler.issueAccessToken);
        Spark.post("/credentials/issue", credentialHandler.getResource);
    }

    private void initErrorMapping() {
        Spark.internalServerError(
                "<html><body><h1>Error! Something went wrong!</h1></body></html>");
    }
}
