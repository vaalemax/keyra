package com.portfolio.pswmanager.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.http.HttpStatus;
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

            if (statusCode == 429 && retryAfter != null) {
                model.addAttribute("retryAfter", retryAfter);
            }

            return switch (statusCode) {
                case 403 -> "error/403";
                case 404 -> "error/404";
                case 429 -> "error/429";
                case 500 -> "error/500";
                default -> "error/generic";
            };
        }

        return "error/generic";
    }
}