package com.example.API_Gateway.Config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
@Order(-1)
public class JwtAuthFilter implements GlobalFilter {

    @Value("${jwt.secretKey}")
    private String SECRET;

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();

        if (path.startsWith("/auth/login") ||
            path.startsWith("/auth/signup") ||
            path.startsWith("/OTP/Validate")) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        String token = null;

      
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }

        if (token == null && exchange.getRequest().getCookies().containsKey("token")) {
            List<String> cookieValues = exchange.getRequest()
                    .getCookies()
                    .get("token")
                    .stream()
                    .map(cookie -> cookie.getValue())
                    .toList();

            if (!cookieValues.isEmpty()) {
                String cookieValue = cookieValues.get(0);

                if (cookieValue.startsWith("token=")) {
                    token = cookieValue.substring(6);
                } else if (cookieValue.startsWith("Bearer ")) {
                    token = cookieValue.substring(7);
                } else {
                    token = cookieValue;
                }
            }
        }

        // No token found
        if (token == null || token.isEmpty()) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String username = claims.getSubject();
            String email = claims.get("email", String.class);
            String role = claims.get("role", String.class);
            String userId = String.valueOf(claims.get("userId"));

            ServerHttpRequest modifiedRequest = exchange.getRequest()
                    .mutate()
                    .header("X-USERNAME", username)
                    .header("X-EMAIL", email)
                    .header("X-ROLES", role)
                    .header("X-UserId", userId)
                    .build();

            return chain.filter(
                    exchange.mutate().request(modifiedRequest).build()
            );

        } catch (Exception e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }
}
