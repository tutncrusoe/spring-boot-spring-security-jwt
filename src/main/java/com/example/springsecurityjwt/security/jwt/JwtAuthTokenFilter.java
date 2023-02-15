package com.example.springsecurityjwt.security.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.example.springsecurityjwt.security.services.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/*JwtAuthTokenFilter validates the Token using JwtProvider:*/
/*OncePerRequestFilter makes a single execution for each request to our API.
It provides a doFilterInternal() method that we will implement parsing & validating JWT, loading User details (using UserDetailsService), checking Authorization (using UsernamePasswordAuthenticationToken).
*JwtAuthTokenFilter extracts username/password from the received token using JwtProvider, then based on the extracted data, JwtAuthTokenFilter:
        – creates a AuthenticationToken (that implements Authentication)
        – uses the AuthenticationToken as Authentication object and stores it in the SecurityContext for future filter uses (e.g: Authorization filters). */
public class JwtAuthTokenFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthTokenFilter.class);

    @Autowired
    private JwtProvider tokenProvider;

    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            /*
            JwtAuthTokenFilter extracts username/password from the received token using JwtProvider, then based on the extracted data, JwtAuthTokenFilter:
        – creates a UsernamePasswordAuthenticationToken (that implements Authentication)
        – uses the UsernamePasswordAuthenticationToken as Authentication object and stores it in the SecurityContext for future filter uses (e.g: Authorization filters).

        In this tutorial, we use UsernamePasswordAuthenticationToken:
             */
            String jwt = parseJwt(request);
            if (jwt != null && tokenProvider.validateJwtToken(jwt)) {

                /* if the request has JWT, validate it, parse username from it
                – from username, get UserDetails to create an Authentication object */

                String username = tokenProvider.getUserNameFromJwtToken(jwt);
                UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(username);

                /*create AuthenticationToken*/
                /* UsernamePasswordAuthenticationToken gets {username, password} from login Request, AuthenticationManager will use it to authenticate a login account. */
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Store Authentication object in SecurityContext
                /* getContext() returns an instance of SecurityContext interface that holds the Authentication and possibly request-specific security information.
                – set the current UserDetails in SecurityContext using setAuthentication(authentication) method. */
                SecurityContextHolder.getContext().setAuthentication(authentication);

                /*After this, everytime you want to get UserDetails, just use SecurityContext like this:
                UserDetails userDetails =
                        (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal(); */
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        filterChain.doFilter(request, response);
    }

    /* get JWT from the Authorization header (by removing Bearer prefix)*/
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7, headerAuth.length());
        }

        return null;
    }
}
