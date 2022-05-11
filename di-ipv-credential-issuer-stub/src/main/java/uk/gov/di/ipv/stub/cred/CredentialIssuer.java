package uk.gov.di.ipv.stub.cred;

import spark.Spark;
import uk.gov.di.ipv.stub.cred.auth.ClientJwtVerifier;
import uk.gov.di.ipv.stub.cred.config.CredentialIssuerConfig;
import uk.gov.di.ipv.stub.cred.handlers.AuthorizeHandler;
import uk.gov.di.ipv.stub.cred.handlers.CredentialHandler;
import uk.gov.di.ipv.stub.cred.handlers.TokenHandler;
import uk.gov.di.ipv.stub.cred.service.AuthCodeService;
import uk.gov.di.ipv.stub.cred.service.CredentialService;
import uk.gov.di.ipv.stub.cred.service.TokenService;
import uk.gov.di.ipv.stub.cred.utils.ViewHelper;
import uk.gov.di.ipv.stub.cred.validation.Validator;
import uk.gov.di.ipv.stub.cred.vc.VerifiableCredentialGenerator;

public class CredentialIssuer {

    private final AuthorizeHandler authorizeHandler;
    private final TokenHandler tokenHandler;
    private final CredentialHandler credentialHandler;

    public CredentialIssuer() {
        Spark.staticFileLocation("/public");
        Spark.port(Integer.parseInt(CredentialIssuerConfig.PORT));

        AuthCodeService authCodeService = new AuthCodeService();
        TokenService tokenService = new TokenService();
        Validator validator = new Validator(authCodeService);
        ClientJwtVerifier clientJwtVerifier = new ClientJwtVerifier();
        CredentialService credentialService = new CredentialService();
        VerifiableCredentialGenerator vcGenerator = new VerifiableCredentialGenerator();

        authorizeHandler =
                new AuthorizeHandler(new ViewHelper(), authCodeService, credentialService);
        tokenHandler =
                new TokenHandler(authCodeService, tokenService, validator, clientJwtVerifier);
        credentialHandler = new CredentialHandler(credentialService, tokenService, vcGenerator);

        initRoutes();
        initErrorMapping();
    }

    private void initRoutes() {
        Spark.get("/authorize", authorizeHandler.doAuthorize);
        Spark.post("/authorize", authorizeHandler.generateResponse);
        Spark.post("/token", tokenHandler.issueAccessToken);
        Spark.get("/credentials/issue", credentialHandler.getResource);
    }

    private void initErrorMapping() {
        Spark.internalServerError(
                "<html><body><h1>Error! Something went wrong!</h1></body></html>");
    }
}
