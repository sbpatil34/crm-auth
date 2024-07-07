package com.crm.crmauth.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.beans.factory.annotation.Value;
import java.io.IOException;
import java.util.Collections;

// Filter class for validating api token
// This will be called for every request
@Component
public class ApiKeyAuthFilter extends OncePerRequestFilter {
    @Value("${api.key}")
    private String apiKey;
    @Value("${api.secret}")
    private String apiSecret;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String apiKeyFromHeader = request.getHeader("X-API-KEY");
        String apiSecretFromHeader = request.getHeader("X-API-SECRET");
        if(apiKey.equals(apiKeyFromHeader) && apiSecret.equals(apiSecretFromHeader)){
            //apiKey is valid. Signal to Spring Security, this is an authenticated request
            var authenticationToken = new UsernamePasswordAuthenticationToken(apiKeyFromHeader,
                    apiKeyFromHeader, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            filterChain.doFilter(request, response);
        }else{
            // reject the request
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write("Unauthorized");
        }
    }
}
