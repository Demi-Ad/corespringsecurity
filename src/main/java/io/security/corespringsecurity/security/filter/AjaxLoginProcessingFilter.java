package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));

    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {

        if (!isAJax(httpServletRequest)) {
            throw new IllegalStateException("Authentication is not supported");
        }

        AccountDto accountDto = objectMapper.readValue(httpServletRequest.getReader(), AccountDto.class);

        if (StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword()))
            throw new IllegalArgumentException("Username or Password is empty");

        AjaxAuthenticationToken authenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(),accountDto.getPassword());

        return getAuthenticationManager().authenticate(authenticationToken);
    }

    private boolean isAJax(HttpServletRequest httpServletRequest) {

        return "XMLHttpRequest".equals(httpServletRequest.getHeader("X-Requested-With"));
    }


}
