package com.dsp.auth.server.conf.handlers;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

@Slf4j
public class MyLogoutSuccessHandler implements LogoutSuccessHandler {

    @Override
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {
        try {
            // 发邮件
            System.out.println("Logout,发邮件事件...");
            // 发短信
            System.out.println("Logout,发短信事件...");
            // 发微信
            System.out.println("Logout,发微信事件...");
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
        }
    }
}
