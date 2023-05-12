package com.dsp.auth.server.conf.handlers;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private static final Logger logger = LoggerFactory.getLogger(MyAuthenticationFailureHandler.class);

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        // Result<String> result = null;
        // response.setStatus(result.getStatus());
        renderJson(response, "MyAuthenticationFailureHandler", MediaType.APPLICATION_JSON.toString());
    }

    public static void renderJson(HttpServletResponse response, Object obj, String type) {
        try {
            response.setContentType(type);
            response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
            response.getWriter().print(JSON.toJSONString(obj));
            response.getWriter().flush();
            response.getWriter().close();
        } catch (IOException e) {
            logger.error("Render response to Json error!");
        }
    }
}
