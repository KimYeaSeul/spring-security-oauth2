package com.example.authorizationserver.filter;

import com.example.authorizationserver.domain.ClientRepository;
import com.example.authorizationserver.domain.ResourceIdService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class CustomResourceIdFilter extends OncePerRequestFilter {

    private final ResourceIdService resourceIdService;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof OAuth2Authentication) {
            OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authentication;
            String clientId = oAuth2Authentication.getOAuth2Request().getClientId();
            String resourceId = resourceIdService.getResourceIdForClient(clientId);

            // resourceId를 요청 속성에 설정
            request.setAttribute("dynamicResourceId", resourceId);
        }

        filterChain.doFilter(request, response);
    }
}