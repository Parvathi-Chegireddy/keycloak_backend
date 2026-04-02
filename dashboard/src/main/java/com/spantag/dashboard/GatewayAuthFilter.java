package com.spantag.dashboard;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * FIX: Removed the "SecurityContextHolder.getContext().getAuthentication() == null" check.
 * Spring Security's AnonymousAuthenticationFilter sets a non-null anonymous auth before
 * this filter runs. The old null-check caused this filter to always skip, leaving the
 * request as anonymous → 401 on all protected endpoints.
 *
 * Now: if X-Auth-Username is present (gateway validated the JWT), always set real auth.
 */
@Component
public class GatewayAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String username = request.getHeader("X-Auth-Username");
        String role     = request.getHeader("X-Auth-Role");

        if (username != null && !username.isBlank()) {
            List<SimpleGrantedAuthority> authorities = role != null && !role.isBlank()
                    ? List.of(new SimpleGrantedAuthority(role))
                    : List.of();

            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(username, null, authorities));
        }

        filterChain.doFilter(request, response);
    }
}