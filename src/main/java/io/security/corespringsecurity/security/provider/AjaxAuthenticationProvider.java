package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import io.security.corespringsecurity.security.service.CustomUserDetails;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class AjaxAuthenticationProvider implements AuthenticationProvider {

    private final CustomUserDetails userDetails;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String userName = authentication.getName();
        String password = (String) authentication.getCredentials();

        AccountContext accountContext = (AccountContext) userDetails.loadUserByUsername(userName);

        if (!passwordEncoder.matches(password,accountContext.getPassword())) {
            throw new BadCredentialsException("badCredentialsException");
        }

        return new AjaxAuthenticationToken(
                accountContext.getAccount(),
                null,
                accountContext.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.equals(AjaxAuthenticationToken.class);
    }
}
