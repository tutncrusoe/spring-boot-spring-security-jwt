package com.example.springsecurityjwt.security;

import com.example.springsecurityjwt.security.services.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.springsecurityjwt.security.jwt.AuthEntryPointExceptionHandler;
import com.example.springsecurityjwt.security.jwt.JwtAuthTokenFilter;

/* Spring Security provides some annotations for pre and post-invocation authorization checks,
filtering of submitted collection arguments or return values: @PreAuthorize, @PreFilter, @PostAuthorize and @PostFilter.
To enable Method Security Expressions, we use @EnableGlobalMethodSecurity annotation:

@EnableGlobalMethodSecurity provides AOP security on methods.
It enables @PreAuthorize, @PostAuthorize, it also supports JSR-250.
 You can find more parameters in configuration in Method Security Expressions. */
@Configuration
@EnableGlobalMethodSecurity(
        // securedEnabled = true,
        // jsr250Enabled = true,
        prePostEnabled = true)

/* WebSecurityConfig is the crux of our security implementation.
 It configures cors, csrf, session management, rules for protected resources.
 We can also extend and customize the default configuration that contains the elements below. */
public class WebSecurityConfig { // extends WebSecurityConfigurerAdapter {

    /* Configuring this provider is simple with AuthenticationManagerBuilder:
    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsServiceImpl).passwordEncoder(passwordEncoder());
    } */

    // Step 1
    private final AuthEntryPointExceptionHandler authEntryPointExceptionHandler;

    // Step 2.1
    private final UserDetailsServiceImpl userDetailsServiceImpl;

    public WebSecurityConfig(AuthEntryPointExceptionHandler authEntryPointExceptionHandler, UserDetailsServiceImpl userDetailsServiceImpl) {
        this.authEntryPointExceptionHandler = authEntryPointExceptionHandler;
        System.out.println("authEntryPointExceptionHandler + UserDetailsServiceImpl");
        this.userDetailsServiceImpl = userDetailsServiceImpl;
    }

    // Step 2.2
    @Bean
    protected PasswordEncoder passwordEncoder() {
        System.out.println("passwordEncoder()");
        return new BCryptPasswordEncoder();
    }

    // Step 2
    /* DaoAuthenticationProvider works well with form-based logins or HTTP Basic authentication which submits a simple username/password authentication request.
    It authenticates the User simply by comparing the password submitted in a UsernamePasswordAuthenticationToken against the one loaded by the UserDetailsService (as a DAO):

    DaoAuthenticationProvider also uses UserDetailsService for getting UserDetails object. This is the common approach in which we only pass a String-based ‘username’ argument and returns a UserDetails: */
    @Bean
    protected DaoAuthenticationProvider authenticationProvider() {
        System.out.println("authenticationProvider()");

        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();

        authenticationProvider.setUserDetailsService(userDetailsServiceImpl);
        authenticationProvider.setPasswordEncoder(passwordEncoder());

        return authenticationProvider;
    }

    // Step 3
    @Bean
    public JwtAuthTokenFilter jwtAuthTokenFilter() {
        System.out.println("JwtAuthTokenFilter()");
        return new JwtAuthTokenFilter();
    }

    // Step 0
    /* Receive HTTP Request: When a HTTP request comes (from a browser, a web service client, an HttpInvoker or an AJAX application – Spring doesn't care),
    it will go through a chain of filters for authentication and authorization purposes.

    So, it is also true for a User Authentication request, that filter chain will be applied until relevant Authentication Filter is found.

    It tells Spring Security how we configure CORS and CSRF,
        when we want to require all users to be authenticated or not,
        which filter (JwtAuthTokenFilter) and when we want it to work (filter before UsernamePasswordAuthenticationFilter),
        which Exception Handler is chosen (AuthEntryPointExceptionHandler). */
    /* To help Spring Security know when we want to require all users to be authenticated,
    which Exception Handler to be chosen, which filter and when we want it to work. */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        System.out.println("filterChain()");
        http.cors().and().csrf().disable()
                .exceptionHandling().authenticationEntryPoint(authEntryPointExceptionHandler)
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/api/auth/**").permitAll()
                .antMatchers("/api/test/**").permitAll()
                .anyRequest().authenticated();

        http.authenticationProvider(authenticationProvider());

        http.addFilterBefore(jwtAuthTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // Step 4
    /* Delegate AuthenticationToken for AuthenticationManager:
    - After AuthenticationToken object was created, it will be used as input parameter for authenticate() method of the AuthenticationManager:
    - We can see that AuthenticationManager is just an interface, the default implementation in Spring Security is ProviderManager:

    AuthenticationManager has a DaoAuthenticationProvider (with help of UserDetailsService & PasswordEncoder) to validate UsernamePasswordAuthenticationToken object.
    If successful, AuthenticationManager returns a fully populated Authentication object (including granted authorities).*/
    @Bean
    protected AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        System.out.println("authenticationManager()");
        return authConfig.getAuthenticationManager();
    }
}
