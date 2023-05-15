package com.dsp.auth.server.rest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DefaultController {

    @GetMapping("/")
    public String root() {
        return "redirect:/index";
    }

    @GetMapping("/index")
    public String index() {
        return "index";
    }

    @GetMapping("/messages")
    public String[] getMessages() {
        return new String[]{"Message 1", "Message 2", "Message 3"};
    }
}
