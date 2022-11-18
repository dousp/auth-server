package com.dsp.auth.server.conf;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties("oauth2.security")
public class Oauth2SecurityProperties {

	private String keyPath;

	private String keyAlias;

	private String keyPass;


	/**
	 * token 有效期， 分钟为单位
	 */
	private Long accessTokenValidityMinutes = 30L;
	/**
	 * refreshToken 有效期， 分钟为单位
	 */
	private Long refreshTokenValidityMinutes = 180L;


}
