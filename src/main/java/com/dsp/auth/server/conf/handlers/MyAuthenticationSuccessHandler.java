package com.dsp.auth.server.conf.handlers;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;

@Slf4j
public class MyAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        super.onAuthenticationSuccess(request, response, authentication);
        try {
            // 发邮件
            System.out.println("发邮件事件...");
            // 发短信
            System.out.println("发短信事件...");
            // 发微信
            System.out.println("发微信事件...");
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
        }
    }
}
