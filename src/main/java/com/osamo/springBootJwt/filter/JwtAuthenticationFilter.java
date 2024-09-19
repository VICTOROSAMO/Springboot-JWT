package com.osamo.springBootJwt.filter;

import com.osamo.springBootJwt.service.JwtService;
import com.osamo.springBootJwt.service.UserDetailServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailServiceImpl userDetailService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailServiceImpl userDetailService) {
        this.jwtService = jwtService;
        this.userDetailService = userDetailService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException { String requestPath = request.getServletPath();

        // Skip JWT validation for login and register routes
        if (requestPath.equals("/login") || requestPath.equals("/register")) {
            filterChain.doFilter(request, response);
            return; // Skip the filter chain further processing
        }




        String authHeader = request.getHeader("Authorization");



        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        String token = authHeader.substring(7);
        String username = jwtService.extractUsername(token);

         if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
             UserDetails userDetails = userDetailService.loadUserByUsername(username);

             if(jwtService.isValid(token,userDetails)){
                 UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                         userDetails, null, userDetails.getAuthorities()
                 );
                 authToken.setDetails(
                         new WebAuthenticationDetailsSource().buildDetails(request)
                 );

                 SecurityContextHolder.getContext().setAuthentication(authToken);
             }

         }
          filterChain.doFilter(request, response);
    }
}
