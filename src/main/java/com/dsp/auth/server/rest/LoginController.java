package com.dsp.auth.server.rest;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@Slf4j
public class LoginController {

    @RequestMapping(path = "/login", method = RequestMethod.GET)
    public String login(HttpServletRequest request) {

        return "login";
    }

    @RequestMapping(path = "/logout", method = RequestMethod.GET)
    public String logout() {
        log.info("logout...");
        return "login";
    }

}
