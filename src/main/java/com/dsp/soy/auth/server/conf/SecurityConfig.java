package com.dsp.soy.auth.server.conf;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
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
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {


    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the authorization server filter chain
                // 允许用户使用基于表单的登录进行身份验证
                .formLogin(Customizer.withDefaults())
        // 允许用户使用 HTTP Basic 身份验证进行身份验证
        // .httpBasic(Customizer.withDefaults())
        ;
        return http.build();
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
