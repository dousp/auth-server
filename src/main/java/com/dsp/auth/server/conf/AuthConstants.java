package com.dsp.auth.server.conf;

public interface AuthConstants {

    String[] DEFAULT_IGNORED_STATIC_RESOURCES = {"/plugins/**", "/stomp/ws"};
    String[] DEFAULT_WEB_STATIC_RESOURCES = {"/error/**", "/static/**", "/assets/**", "/webjars/**", "/favicon.ico"};
    String[] DEFAULT_LOGIN_RESOURCES = {"/authorization/**", "/oauth2/sign-out", "/login", "/client/**"};
    String[] DEFAULT_DOC_STATIC_RESOURCES = {"/swagger-ui.html", "/swagger-ui/**", "/swagger-resources/**", "/v3/api-docs", "/v3/api-docs/**", "/openapi.json"};

    String AUTHORIZATION_CODE = "authorization_code";
    String IMPLICIT = "implicit";
    String PASSWORD = "password";
    String CLIENT_CREDENTIALS = "client_credentials";
    String REFRESH_TOKEN = "refresh_token";

    String AUTHORIZATION_ENDPOINT = "/oauth2/authorize";
    String TOKEN_ENDPOINT = "/oauth2/token";
    String JWK_SET_ENDPOINT = "/oauth2/jwks";
    String TOKEN_REVOCATION_ENDPOINT = "/oauth2/revoke";
    String TOKEN_INTROSPECTION_ENDPOINT = "/oauth2/introspect";
    String OAUTH_CONSENT_PAGE = "/oauth2/consent";

    String BEARER_TYPE = "Bearer";
    String BEARER_TOKEN = BEARER_TYPE + " ";
    String BASIC_TYPE = "Basic";
    String BASIC_TOKEN = BASIC_TYPE + " ";
    String ROLE_PREFIX = "ROLE_";
    String AUTHORITIES = "authorities";
}
