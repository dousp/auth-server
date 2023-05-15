/*
    数据倒入
*/


-- ----------------------------
-- Records of oauth2_registered_client
-- ----------------------------

INSERT INTO `auth`.`oauth2_registered_client` (`id`, `client_id`, `client_id_issued_at`, `client_secret`,
                                               `client_secret_expires_at`, `client_name`,
                                               `client_authentication_methods`, `authorization_grant_types`,
                                               `redirect_uris`, `scopes`, `client_settings`, `token_settings`)
VALUES ('e255ba29-fe42-4236-93ce-f09d85e62f0a', 'ddd', '2022-12-03 11:38:32', '{noop}ddd', NULL, '豆豆',
        'client_secret_post,private_key_jwt,client_secret_jwt,client_secret_basic',
        'refresh_token,client_credentials,authorization_code,urn:ietf:params:oauth:grant-type:jwt-bearer',
        'http://127.0.0.1:8080/authorized,https://baidu.com,http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc',
        'openid,USER,msg.read,msg.write',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"settings.client.require-proof-key\":false,\"settings.client.require-authorization-consent\":true}',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"settings.token.reuse-refresh-tokens\":true,\"settings.token.id-token-signature-algorithm\":[\"org.springframework.security.oauth2.jose.jws.SignatureAlgorithm\",\"RS256\"],\"settings.token.access-token-time-to-live\":[\"java.time.Duration\",3600.000000000],\"settings.token.access-token-format\":{\"@class\":\"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat\",\"value\":\"self-contained\"},\"settings.token.refresh-token-time-to-live\":[\"java.time.Duration\",10800.000000000],\"settings.token.authorization-code-time-to-live\":[\"java.time.Duration\",300.000000000]}');



-- ----------------------------
-- Records of authorities
-- ----------------------------
INSERT INTO `authorities`(`username`, `authority`)
VALUES ('dd', 'user');

-- ----------------------------
-- Records of users
-- ----------------------------
INSERT INTO `users`(`username`, `password`, `enabled`)
VALUES ('dd', '{noop}dd', 1);

-- password：password
INSERT INTO `users`(`username`, `password`, `enabled`)
VALUES ('dd2', '{bcrypt}$2a$10$UZ03njp0Y3AY.2Rvf46CWO.9NTC5y3/yHX6b3Ha9r4by6tPTIhpre', 1);