package com.nazndev.apigwservice.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class CustomExceptionHandlingFilter implements GlobalFilter {

    private static final Logger logger = LoggerFactory.getLogger(CustomExceptionHandlingFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return chain.filter(exchange).doOnError(throwable -> {
            logger.error("Error occurred while processing the request: {}", throwable.getMessage());

            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

            String errorMessage = "{\"error\": \"An internal server error occurred. Please try again later.\"}";
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(errorMessage.getBytes());

            exchange.getResponse().writeWith(Mono.just(buffer)).subscribe();
        });
    }
}
