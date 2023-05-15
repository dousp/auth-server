package com.dsp.auth.server.conf.handlers;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * 在资源服务器中 不携带token 或者token无效  401
 */
@Slf4j
public class SimpleAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException, IOException {
        if (response.isCommitted()) {
            return;
        }

        Throwable throwable = authException.fillInStackTrace();

        String errorMessage = "认证失败";

        if (throwable instanceof BadCredentialsException) {
            errorMessage = "错误的客户端信息";
        } else {
            Throwable cause = authException.getCause();

            if (cause instanceof JwtValidationException) {

                log.warn("JWT Token 过期，具体内容:" + cause.getMessage());
                errorMessage = "无效的token信息";

            } else if (cause instanceof BadJwtException) {

                log.warn("JWT 签名异常，具体内容：" + cause.getMessage());
                errorMessage = "无效的token信息";

            } else if (cause instanceof AccountExpiredException) {

                log.warn("账户已过期：" + cause.getMessage());
                errorMessage = "账户已过期";

            } else if (cause instanceof LockedException) {
                log.warn("账户已被锁定：" + cause.getMessage());
                errorMessage = "账户已被锁定";

            } else if (throwable instanceof InsufficientAuthenticationException) {
                String message = throwable.getMessage();
                if (message.contains("Invalid token does not contain resource id")) {
                    errorMessage = "未经授权的资源服务器";

                } else if (message.contains("Full authentication is required to access this resource")) {
                    errorMessage = "缺少验证信息";

                }
            } else {
                errorMessage = "验证异常";
            }
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setCharacterEncoding("utf-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        PrintWriter printWriter = response.getWriter();
        String resBody = JSON.toJSONString(errorMessage);
        printWriter.print(resBody);
        printWriter.flush();
        printWriter.close();
    }
}
