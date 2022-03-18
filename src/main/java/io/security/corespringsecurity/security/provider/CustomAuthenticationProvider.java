package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.security.service.AccountDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String userName = authentication.getName();
        String password = (String) authentication.getCredentials();

        AccountDetails accountDetails = (AccountDetails) userDetailsService.loadUserByUsername(userName);

        if (!passwordEncoder.matches(password,accountDetails.getPassword())) {
            throw new BadCredentialsException("badCredentialsException");
        }

        return new UsernamePasswordAuthenticationToken(
                accountDetails.getAccount(),
                null,
                accountDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(aClass);
    }
}