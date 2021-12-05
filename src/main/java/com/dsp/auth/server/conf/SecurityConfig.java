package com.dsp.auth.server.conf;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * 默认安全配置
 *
 * @author shupeng.dou
 * @version 2021年12月01日 18:03
 */
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
				.csrf().disable()
				.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
						authorizationManagerRequestMatcherRegistry.anyRequest().authenticated()
				)
				.formLogin(Customizer.withDefaults())
		;

		return httpSecurity.build();
	}


	@Bean
	UserDetailsService userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("dd")
				.password("dd")
				// .passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder()::encode)
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}

	/**
	 * Web security customizer web security customizer.
	 *
	 * @return the web security customizer
	 */
	@Bean
	WebSecurityCustomizer webSecurityCustomizer() {
		return web -> web.ignoring().antMatchers("/actuator/health", "/h2-console/**");
	}


}
