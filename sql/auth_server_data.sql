/*
    数据倒入
*/


-- ----------------------------
-- Records of oauth2_registered_client
-- ----------------------------
INSERT INTO `oauth2_registered_client`(`id`,
                                       `client_id`,
                                       `client_id_issued_at`,
                                       `client_secret`,
                                       `client_secret_expires_at`,
                                       `client_name`,
                                       `client_authentication_methods`,
                                       `authorization_grant_types`,
                                       `redirect_uris`,
                                       `scopes`,
                                       `client_settings`,
                                       `token_settings`)
VALUES ('36bf1689-3d71-4fb1-a88a-5ebf5cc5c5d7',
        'xuxiaowei_client_id',
        '2022-05-30 08:56:58',
        '{noop}xuxiaowei_client_secret',
        NULL,
        '36bf1689-3d71-4fb1-a88a-5ebf5cc5c5d7',
        'client_secret_post,client_secret_basic',
        'refresh_token,implicit,client_credentials,authorization_code',
        'http://127.0.0.1:1401/code',
        'snsapi_base',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"settings.client.require-proof-key\":false,\"settings.client.require-authorization-consent\":true}',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"settings.token.reuse-refresh-tokens\":true,\"settings.token.id-token-signature-algorithm\":[\"org.springframework.security.oauth2.jose.jws.SignatureAlgorithm\",\"RS256\"],\"settings.token.access-token-time-to-live\":[\"java.time.Duration\",300.000000000],\"settings.token.access-token-format\":{\"@class\":\"org.springframework.security.oauth2.core.OAuth2TokenFormat\",\"value\":\"self-contained\"},\"settings.token.refresh-token-time-to-live\":[\"java.time.Duration\",3600.000000000]}');

INSERT INTO `oauth2_registered_client`(`id`,
                                       `client_id`,
                                       `client_id_issued_at`,
                                       `client_secret`,
                                       `client_secret_expires_at`,
                                       `client_name`,
                                       `client_authentication_methods`,
                                       `authorization_grant_types`,
                                       `redirect_uris`,
                                       `scopes`,
                                       `client_settings`,
                                       `token_settings`)
VALUES ('570d9f37-8a95-4a74-a1f0-fb913b78aeca',
        'messaging-client',
        '2022-05-30 08:56:58',
        '{noop}secret',
        NULL,
        '570d9f37-8a95-4a74-a1f0-fb913b78aeca',
        'client_secret_post,client_secret_basic',
        'refresh_token,client_credentials,authorization_code',
        'http://127.0.0.1:1401/login/oauth2/code/messaging-client-oidc,http://127.0.0.1:1401/authorized',
        'openid,message.read,message.write',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"settings.client.require-proof-key\":false,\"settings.client.require-authorization-consent\":true}',
        '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"settings.token.reuse-refresh-tokens\":true,\"settings.token.id-token-signature-algorithm\":[\"org.springframework.security.oauth2.jose.jws.SignatureAlgorithm\",\"RS256\"],\"settings.token.access-token-time-to-live\":[\"java.time.Duration\",300.000000000],\"settings.token.access-token-format\":{\"@class\":\"org.springframework.security.oauth2.core.OAuth2TokenFormat\",\"value\":\"self-contained\"},\"settings.token.refresh-token-time-to-live\":[\"java.time.Duration\",3600.000000000]}');


-- ----------------------------
-- Records of authorities
-- ----------------------------
INSERT INTO `authorities`(`username`, `authority`)
VALUES ('dd', 'user');

-- ----------------------------
-- Records of users
-- ----------------------------
INSERT INTO `users`(`username`, `password`, `enabled`)
VALUES ('dd', '{bcrypt}$2a$10$UZ03njp0Y3AY.2Rvf46CWO.9NTC5y3/yHX6b3Ha9r4by6tPTIhpre', 1);