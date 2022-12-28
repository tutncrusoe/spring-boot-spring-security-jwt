package com.example.springsecurityjwt.security.jwt;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

/*– AuthEntryPointExceptionHandler will catch authentication error.

If the user requests a secure HTTP resource without being authenticated, AuthEntryPointExceptionHandler will be called.
At this time, an AuthenticationException is thrown, commence() method on the entry point is triggered:*/

/*Now we create AuthEntryPointExceptionHandler class that implements AuthenticationEntryPoint interface.
Then we override the commence() method.
This method will be triggered anytime unauthenticated User requests a secured HTTP resource and an AuthenticationException is thrown.*/
@Component
public class AuthEntryPointExceptionHandler implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointExceptionHandler.class);

    /* AuthEntryPointExceptionHandler handles AuthenticationException. */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException {
        logger.error("Unauthorized error: {}", authException.getMessage());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        /*HttpServletResponse.SC_UNAUTHORIZED is the 401 Status code.
        It indicates that the request requires HTTP authentication.

        We’ve already built all things for Spring Security.
        The next sections of this tutorial will show you how to implement Controllers for our RestAPIs.*/
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        final Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error", "Unauthorized");
        body.put("message", authException.getMessage());
        body.put("path", request.getServletPath());

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }

}
