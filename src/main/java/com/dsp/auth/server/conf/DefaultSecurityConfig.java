package com.dsp.auth.server.conf;

import com.dsp.auth.server.conf.handlers.SimpleAccessDeniedHandler;
import com.dsp.auth.server.conf.handlers.SimpleAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

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
        http.csrf().disable().cors();
        http
                // .securityMatcher("/index/**")
                // .securityMatcher("/messages/**")
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers(AuthConstants.DEFAULT_IGNORED_STATIC_RESOURCES).permitAll()
                        .requestMatchers(AuthConstants.DEFAULT_WEB_STATIC_RESOURCES).permitAll()
                        .requestMatchers(AuthConstants.DEFAULT_LOGIN_RESOURCES).permitAll()
                        .requestMatchers(AuthConstants.DEFAULT_DOC_STATIC_RESOURCES).permitAll()
                        .requestMatchers(HttpMethod.OPTIONS).permitAll()
                        // .requestMatchers("/index*").hasAuthority("SCOPE_msg.read")
                        // .requestMatchers("/messages/**").hasAuthority("SCOPE_msg.read")
                        .anyRequest().authenticated()
                );

        // 允许用户使用基于表单的登录进行身份验证
        http.formLogin().loginPage("/login");
        http.oauth2ResourceServer(oauth2ResourceServer ->
                oauth2ResourceServer.jwt()
                        .and()
                        .accessDeniedHandler(new SimpleAccessDeniedHandler())
                        .authenticationEntryPoint(new SimpleAuthenticationEntryPoint())
        );
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

}
