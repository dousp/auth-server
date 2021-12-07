package com.dsp.auth.server.conf;

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
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
 */
@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

	/**
	 * 授权服务器默认设置
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		// 默认的话就用这个
		// OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		// 参看 OAuth2AuthorizationServerConfiguration.applyDefaultSecurity#applyDefaultSecurity
		OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer
				= new OAuth2AuthorizationServerConfigurer<>();
		// 可以根据需求对OAuth2AuthorizationServerConfiguration进行个性化设置
		RequestMatcher endpointsMatcher
				= authorizationServerConfigurer.getEndpointsMatcher();
		// 授权服务器相关请求端点
		http
				.requestMatcher(endpointsMatcher)
				.authorizeRequests(authorizeRequests ->
						authorizeRequests.anyRequest().authenticated()
				)
				.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
				.formLogin(Customizer.withDefaults())
				// 授权服务器配置
				.apply(authorizationServerConfigurer);
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

		// JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

		RegisteredClient client = RegisteredClient
				.withId("ddd")
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
					authorizationGrantTypes.add(AuthorizationGrantType.PASSWORD);
				})
				// 回调地址名单，不在此列将被拒绝 而且只能使用IP或者域名  不能使用 localhost
				.redirectUri("https://baidu.com")
				// .redirectUri("http://127.0.0.1:8080/authorized")
				// JWT的配置项 包括TTL  是否复用refreshToken等等
				.scope("USER")
				.scope("msg.write")
				.scope("msg.read")
				.tokenSettings(TokenSettings.builder().build())
				// 配置客户端相关的配置项，包括验证密钥或者 是否需要授权页面
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();

		// 初始化一个客户端到db中
		// registeredClientRepository.save(client);
		// return registeredClientRepository;

		// 使用内存模式
		return new InMemoryRegisteredClientRepository(client);
	}

	/**
	 * 配置oauth2 provider setting
	 */
	@Bean
	public ProviderSettings providerSettings(@Value("${server.port}") Integer port) {
		return ProviderSettings.builder().issuer("http://auth-server:" + port).build();
	}

	@Bean
	@SneakyThrows
	public JWKSource<SecurityContext> jwkSource() {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

}
