package com.dsp.auth.server.conf;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationServerMetadataEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretPostAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.JwtClientAssertionAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.PublicClientAuthenticationConverter;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.annotation.Resource;
import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;


/**
 * 授权服务器配置
 *
 * @author shupeng.dou
 * @version 2021年12月01日 18:14
 * <p>
 * 0. spring-security-oauth2-authorization-server-*.*.*.jar
 * 1. SQL
 * \org\springframework\security\oauth2\server\authorization\client\oauth2-registered-client-schema.sql<p>
 * \org\springframework\security\oauth2\server\authorization\oauth2-authorization-consent-schema.sql<p>
 * \org\springframework\security\oauth2\server\authorization\oauth2-authorization-schema.sql<p>
 * <p>
 * 以下来自gitee作者xuxiaowei整理
 * </p>
 * @see OAuth2AuthorizationServerConfiguration OAuth 2.0 授权服务器支持的 {@link Configuration} 。
 * @see UserDetailsServiceAutoConfiguration
 * @see OAuth2AuthorizationEndpointFilter /oauth2/authorize
 * @see AuthorizationServerSettings#builder() /oauth2/authorize、/oauth2/token、/oauth2/jwks、/oauth2/revoke、/oauth2/introspect、/connect/register、/userinfo
 * @see OAuth2AuthorizationService 此接口的实现负责OAuth 2.0 Authorization(s)的管理。
 * @see InMemoryOAuth2AuthorizationService 一个 {@link OAuth2AuthorizationService} 存储 {@link OAuth2Authorization} 的内存。
 * @see JdbcOAuth2AuthorizationService {@link OAuth2AuthorizationService} 的 JDBC 实现，
 * 它使用 {@link org.springframework.jdbc.core.JdbcOperations} 进行 {@link OAuth2Authorization} 持久性。
 * @see OAuth2AuthorizationConsentService 此接口的实现负责管理 {@link OAuth2AuthorizationConsent} OAuth 2.0 Authorization Consent(s) 。
 * @see InMemoryOAuth2AuthorizationConsentService 一个 {@link OAuth2AuthorizationConsentService} 存储 {@link OAuth2AuthorizationConsent} 的内存。
 * @see JdbcOAuth2AuthorizationConsentService {@link OAuth2AuthorizationConsentService} 的 JDBC 实现，
 * 它使用 {@link org.springframework.jdbc.core.JdbcOperations} 进行 {@link OAuth2AuthorizationConsent} 持久性。
 * @see RegisteredClientRepository OAuth 2.0 {@link RegisteredClient} (s) 的存储库。
 * @see InMemoryRegisteredClientRepository 在内存中存储 {@link RegisteredClientRepository} (s) 的 {@link RegisteredClient} 。
 * @see JdbcRegisteredClientRepository {@link RegisteredClientRepository} 的 JDBC 实现，
 * 它使用 {@link org.springframework.jdbc.core.JdbcOperations} 进行 {@link RegisteredClient} 持久性。
 * @see OidcScopes
 * @see OAuth2AuthorizationServerMetadataEndpointFilter
 * @see OAuth2ClientAuthenticationFilter OAuth 2.1 客户凭证验证
 * @see JwtClientAssertionAuthenticationConverter 基于 JWT 客户端凭据 验证
 * @see ClientSecretBasicAuthenticationConverter 基于 Basic 客户端凭据 验证
 * @see ClientSecretPostAuthenticationConverter 基于 POST 参数的 客户端凭据 验证
 * @see PublicClientAuthenticationConverter 基于 Proof Key for Code Exchange (PKCE) 对公共客户端进行身份验证
 * @see OAuth2TokenGenerator OAuth2 令牌生成器
 * @see org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeGenerator OAuth2 授权码生成器
 * @see JwtGenerator 生成用于 {@link Jwt} 或 {@link OAuth2TokenGenerator} 的 {@link OAuth2AccessToken} 的 {@link OidcIdToken}。
 * @see DelegatingOAuth2TokenGenerator 一个 {@link OAuth2TokenGenerator}，它简单地委托给它的 {@link OAuth2TokenGenerator} (s) 的内部 List。
 * 每个 {@link OAuth2TokenGenerator} 都有机会使用 {@link OAuth2TokenGenerator#generate(OAuth2TokenContext)} 并返回第一个non-null OAuth2Token 。
 * @see OAuth2AccessTokenGenerator OAuth2 访问令牌生成器
 * @see OAuth2RefreshTokenGenerator 生成 {@link OAuth2TokenGenerator} 的 {@link OAuth2RefreshToken}。
 */
@Configuration(proxyBeanMethods = false)
// @EnableWebSecurity
public class AuthorizationServerConfig {

    @Resource
    private SecurityProperties properties;


    /**
     * 授权服务器的协议端点
     * 授权：赋予已经通过认证的客户相关权限
     * Spring Security 过滤器链
     *
     * @see <a href="https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html">...</a>
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // 默认的话就用这个
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http
                .formLogin(Customizer.withDefaults())
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                // 未从授权端点进行身份验证时重定向到登录页面
                                new LoginUrlAuthenticationEntryPoint("/login"))
                )
                .build();
    }

    /**
     * 配置需要认证的资源，用于身份验证
     * 认证：对使用服务的人的身份核实
     * Spring Security 过滤器链
     *
     * @see <a href="https://docs.spring.io/spring-security/reference/servlet/authentication/index.html">...</a>
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // 允许用户使用 HTTP Basic 身份验证进行身份验证
                // .httpBasic(Customizer.withDefaults())
                // 允许用户使用基于表单的登录进行身份验证
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    /**
     * 用户信息来源
     *
     * @see UserDetailsService 用于检索用户进行身份验证的实例。
     */
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    /**
     * 客户端信息持来源
     * 授权服务器要求客户端必须是已经注册的，避免非法的客户端发起授权申请
     * 实体： RegisteredClient
     *
     * @see RegisteredClientRepository 用于管理客户端的实例。
     * @see ClientAuthenticationMethod 认证方式
     * @see AuthorizationGrantType 授权方式
     * table: oauth2_registered_client
     * 操作该表的JDBC服务接口： RegisteredClientRepository
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /**
     * 授权码、授权Token、刷新Token 持久化
     * OAuth2授权信息持久化，记录授权的资源拥有者（Resource Owner）对某个客户端的某次授权记录
     * <p>实体： OAuth2Authorization</p>
     * <p>table: oauth2_authorization</p>
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 确认授权持久化
     * 资源拥有者（Resource Owner）对授权的确认信息OAuth2AuthorizationConsent的持久化
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
     * @see JWKSource 用于签署访问令牌的实例。
     */
    // @Bean
    // public JWKSource<SecurityContext> jwkSource() {
    //     KeyPair keyPair = generateRsaKey();
    //     RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    //     RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    //     RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
    //     JWKSet jwkSet = new JWKSet(rsaKey);
    //     return new ImmutableJWKSet<>(jwkSet);
    // }

    /**
     * 有需要就的话，就声明一个JwtDecoder进行定制
     *
     * @param jwkSource JSON Web Key (JWK) source
     * @return JwtDecoder
     * @see OAuth2AuthorizationServerConfiguration#jwtDecoder(JWKSource)
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
     * 启动时生成的带有密钥的实例 {@link KeyPair} 用于创建 {@link JWKSource} 上述内容。
     */
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

}
