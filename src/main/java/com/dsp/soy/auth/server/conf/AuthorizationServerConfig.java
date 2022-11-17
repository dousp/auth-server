package com.dsp.soy.auth.server.conf;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.annotation.Resource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

/**
 * 授权服务器配置
 *
 * @author shupeng.dou
 * @version 2021年12月01日 18:14
 */
@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    @Resource
    private Oauth2SecurityProperties properties;


    /**
     * 授权服务器默认设置
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // 默认的话就用这个
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.build();
    }

    /**
     * OAuth2.0客户端信息持久化
     * 授权服务器要求客户端必须是已经注册的，避免非法的客户端发起授权申请
     * 实体： RegisteredClient
     * table: oauth2_registered_client
     * 操作该表的JDBC服务接口： RegisteredClientRepository
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {

        RegisteredClient client = RegisteredClient
                // .withId(UUID.randomUUID().toString())
                .withId("ddd")
                .clientId("ddd")
                // {noop} 这个是说NoOpPasswordEncoder
                // https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html
                .clientSecret("{noop}ddd")
                // 授权方式
                // .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethods(clientAuthenticationMethods -> {
                    clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                    clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
                    clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
                    clientAuthenticationMethods.add(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
                })
                // 授权类型
                // .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantTypes(authorizationGrantTypes -> {
                    authorizationGrantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    authorizationGrantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                    authorizationGrantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                    authorizationGrantTypes.add(AuthorizationGrantType.JWT_BEARER);
                    authorizationGrantTypes.add(AuthorizationGrantType.PASSWORD);
                })
                // 回调地址名单，不在此列将被拒绝 而且只能使用IP或者域名  不能使用 localhost
                .redirectUri("http://mac.dou.com:8080/foo/bar")
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                // 客户端申请的作用域，也可以理解这个客户端申请访问用户的哪些信息
                .scope(OidcScopes.OPENID)
                .scope("USER")
                .scope("msg.write")
                .scope("msg.read")
                // 配置token
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

        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        // 初始化一个客户端到db中
        if (null == registeredClientRepository.findByClientId("ddd")) {
            registeredClientRepository.save(client);
        }
        return registeredClientRepository;
    }

    /**
     * OAuth2授权信息持久化，记录授权的资源拥有者（Resource Owner）对某个客户端的某次授权记录
     * <p>实体： OAuth2Authorization</p>
     * <p>table: oauth2_authorization</p>
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 确认授权持久化，资源拥有者（Resource Owner）对授权的确认信息OAuth2AuthorizationConsent的持久化
     * resource owner已授予client的相关权限信息
     * <p>实体：OAuth2AuthorizationConsent</p>
     * <p>table: oauth2_authorization_consent</p>
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 对JWT进行签名的加解密密钥
     *
     * @return The matching JWKs, empty list if no matches were found.
     */
    @Bean
    @SneakyThrows
    public JWKSource<SecurityContext> jwkSource() {
        // 秘钥信息
        String path = properties.getKeyPath();
        String alias = properties.getKeyAlias();
        String pass = properties.getKeyPass();

        ClassPathResource resource = new ClassPathResource(path);
        KeyStore jks = KeyStore.getInstance("jks");
        char[] pin = pass.toCharArray();
        jks.load(resource.getInputStream(), pin);
        RSAKey rsaKey = RSAKey.load(jks, alias, pin);
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);

        // RSAKey rsaKey = Jwks.generateRsa();
        // JWKSet jwkSet = new JWKSet(rsaKey);
        // return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    /**
     * 有需要就的话，就声明一个JwtDecoder进行定制
     *
     * @param jwkSource JSON Web Key (JWK) source
     * @return JwtDecoder
     */
    @Bean
    public static JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        Set<JWSAlgorithm> jwsAlgorithm = new HashSet<>();
        jwsAlgorithm.addAll(JWSAlgorithm.Family.RSA);
        jwsAlgorithm.addAll(JWSAlgorithm.Family.EC);
        jwsAlgorithm.addAll(JWSAlgorithm.Family.HMAC_SHA);
        JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(jwsAlgorithm, jwkSource);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        // iss: jwt签发者
        // sub: jwt所面向的用户
        // aud: 接收jwt的一方
        // exp: jwt的过期时间，这个过期时间必须要大于签发时间
        // nbf: 定义在什么时间之前，该jwt都是不可用的.
        // iat: jwt的签发时间
        // jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击
        // jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
        //         //exact match claims
        //         validClaims,
        //         //Required claims
        //         new HashSet<>(Arrays.asList("exp", "sub","iss"))));
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
            // todo Override the default Nimbus claims set verifier as NimbusJwtDecoder handles it instead
        });
        return new NimbusJwtDecoder(jwtProcessor);
        // return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 如果有需要的话，定制jwt，进行增强，
     *
     * @return oauth 2 token customizer
     */
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return jwtEncodingContext -> {
            JwsHeader.Builder jwsHeader = jwtEncodingContext.getHeaders();
            jwsHeader.header("client-id", jwtEncodingContext.getRegisteredClient().getClientId())
                    .header("dd", "dd");
            JwtClaimsSet.Builder claims = jwtEncodingContext.getClaims();
            claims.claim("dd", "dd");
            JwtEncodingContext.with(jwtEncodingContext.getHeaders(), claims);
        };
    }

    /**
     * 配置一些端点的路径，比如：获取token、授权端点等
     * 参看{@link org.springframework.security.oauth2.server.authorization.config.ProviderSettings#builder}
     */
    @Bean
    public ProviderSettings providerSettings(@Value("${server.port}") Integer port) {
        return ProviderSettings.builder()
                // 配置获取token的端点路径
                // .tokenEndpoint("/oauth2/token")
                // 发布者的url地址,一般是本系统访问的根路径
                .issuer("http://auth-server.com:" + port)
                .build();
    }

    /**
     * 这个0.4版本才有。。。。
     *
     * @return
     */
    // @Bean
    // public AuthorizationServerSettings authorizationServerSettings() {
    //     return AuthorizationServerSettings.builder().build();
    // }
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}