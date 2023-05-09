package com.dsp.auth.server.rest;

import jakarta.annotation.Resource;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.UUID;

@RestController
@RequestMapping("/info")
public class InfoController {

    @Resource
    private RegisteredClientRepository registeredClientRepository;

    @GetMapping("")
    public String info(){

        return "success";
    }

    @GetMapping("/create/client")
    public String createClient(){
        RegisteredClient client = RegisteredClient
                .withId(UUID.randomUUID().toString())
                // .withId("ddd")
                .clientId("ddd")
                // {noop} 这个是说NoOpPasswordEncoder
                // https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html
                .clientSecret("{noop}ddd")
                // 授权方式
                .clientAuthenticationMethods(clientAuthenticationMethods -> {
                    clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                    clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
                    clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
                    clientAuthenticationMethods.add(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
                })
                // 授权类型
                .authorizationGrantTypes(authorizationGrantTypes -> {
                    authorizationGrantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    authorizationGrantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                    authorizationGrantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                    authorizationGrantTypes.add(AuthorizationGrantType.JWT_BEARER);
                    // 这种方式过时了
                    // authorizationGrantTypes.add(AuthorizationGrantType.PASSWORD);
                })
                // 回调地址名单，不在此列将被拒绝 而且只能使用IP或者域名  不能使用 localhost
                .redirectUri("https://baidu.com")
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                // 客户端申请的作用域，也可以理解这个客户端申请访问用户的哪些信息
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("user")
                .scope("msg.write")
                .scope("msg.read")
                // 配置5token
                // 是否需要用户确认一下客户端需要获取用户的哪些权限
                // 比如：客户端需要获取用户的 用户信息、用户照片 但是此处用户可以控制只给客户端授权获取 用户信息。
                .tokenSettings(TokenSettings.builder()
                        // 是否可重用刷新令牌
                        .reuseRefreshTokens(true)
                        // accessToken 的有效期
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        // refreshToken 的有效期
                        .refreshTokenTimeToLive(Duration.ofHours(3))
                        .build()
                )
                // 配置客户端相关的配置项，包括验证密钥或者 是否需要授权页面
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        registeredClientRepository.save(client);
        RegisteredClient client1 = registeredClientRepository.findByClientId("ddd");
        return "success, client data id: " + client1.getId();
    }
}
