# Digital Identity IPV Core Stub

`di-ipv-core-stub`

## About

An integration stub service for testing credential issuer journeys from a Stub IPV Core.

This stub allows us to:

* configure multiple credential issuers
* set the user identity claim expected in the Experian UAT environment (name, date of birth, UKAddress)
* set the user identity claim explicitly in a form (todo)
* send these claims to a credential issuer
* view the credentials returned

## Config

Core Stub config from the `di-ipv-config` repository directory `/stubs/di-ipv-core-stub` will be available at:
* Docker image: `/app/`
* PaaS: `config/`

## Environment

| Variable                     | Description                                    | Example Value                                                           |
|------------------------------|------------------------------------------------|-------------------------------------------------------------------------|
| CORE_STUB_PORT               | The port number the IPV Core Stub should run on | `8085`                                                                 |
| CORE_STUB_CLIENT_ID          | The id of the IPV Core Stub client             | `ipv-core-stub`                                                         |
| CORE_STUB_REDIRECT_URL       | The OAuth callback url                         | `http://localhost:8085/callback`                                        |
| CORE_STUB_MAX_SEARCH_RESULTS | Max search by name results                     | `200`                                                                   |
| CORE_STUB_USER_DATA_PATH     | File path to Experian user data zip file       | `/app/config/experian-uat-users-large.zip`                              |
| CORE_STUB_CONFIG_FILE        | File path to the credential issuer config      | `/app/config/cris-dev.yaml` for Docker, `config/cris-dev.yaml` for PaaS |
| CORE_STUB_KEYSTORE_BASE64    | Base64 of p12 signing keystore                 |                                                                         |
| CORE_STUB_KEYSTORE_FILE      | File path to p12 signing keystore              |                                                                         |
| CORE_STUB_KEYSTORE_PASSWORD  | password for the p12 signing keystore          | `puppet`                                                                |
| CORE_STUB_KEYSTORE_ALIAS     | alias for key in the p12 signing keystore      | `ipv-core-stub`                                                         |

## Running locally

To run locally in a docker container, you can run the `docker-compose` command. Remember to set the directory for the config files, as given in the [sample .env file](./env.sample)

```shell
docker-compose up
```

This will build the project with gradle in docker and run it.

Configuration is set from the `../../di-ipv-config/stubs/di-ipv-core-stub` directory.

Once started, visit [http://localhost:8085/](http://localhost:8085/).

By clicking on the _Visit Credential Issuers_ button, you will be able to choose which credential issuer to visit.

### Remote Debugging

A remote JVM debugger can be attached on port `8087`