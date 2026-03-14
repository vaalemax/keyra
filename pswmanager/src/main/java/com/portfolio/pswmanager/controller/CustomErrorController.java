package com.portfolio.pswmanager.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class CustomErrorController implements ErrorController {
    private static final Logger log = LoggerFactory.getLogger(CustomErrorController.class);

    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        String uri = (String) request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);
        String message = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);

        Object retryAfter = request.getAttribute("retryAfter");

        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());

            log.warn("HTTP Error {} occurred - URI: {}, Message: {}", statusCode, uri, message);

            model.addAttribute("statusCode", statusCode);
            model.addAttribute("uri", uri);
            model.addAttribute("message", message);

            if (statusCode == 429) {
                if (retryAfter != null) {
                    model.addAttribute("retryAfter", retryAfter);
                } else {
                    model.addAttribute("retryAfter", 60);
                }
            }

            if(statusCode == 403) {
                return "error/403";
            }else if(statusCode == 404) {
                return "error/404";
            }else if(statusCode == 429) {
                return "error/429";
            }else if(statusCode == 500) {
                return "error/500";
            }
        }

        return "error/generic";
    }
}