package com.spantag.Apigatewayapplication;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;

/**
 * Gateway Config — logging filter only.
 *
 * JWT validation and X-Auth-* header injection is handled by
 * KeycloakJwtFilter (route-level filter referenced in application.yml).
 *
 * Security (Keycloak JWT validation via JWKS) is configured in SecurityConfig.
 */
@Configuration
public class GatewayConfig {

    @Bean
    public GlobalFilter loggingFilter() {
        return (exchange, chain) -> {
            ServerHttpRequest req = exchange.getRequest();
            System.out.printf("[GATEWAY] %s %s  Auth: %s%n",
                    req.getMethod(),
                    req.getURI(),
                    req.getHeaders().getFirst(HttpHeaders.AUTHORIZATION) != null
                            ? "Bearer ***" : "none");
            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                ServerHttpResponse res = exchange.getResponse();
                System.out.printf("[GATEWAY] Response: %s%n", res.getStatusCode());
            }));
        };
    }
}
