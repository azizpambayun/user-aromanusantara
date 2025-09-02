package com.harumnusantara.user.service;

import com.harumnusantara.user.model.User;
import com.harumnusantara.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        log.debug("Loading user by username or email: {}", usernameOrEmail);

        User user = userRepository.findByUsernameOrEmail(usernameOrEmail)
                .orElseThrow(() -> {
                    log.error("User Not Found with username or email: {}", usernameOrEmail);
                    return new UsernameNotFoundException(
                            "User Not Found with username or email " + usernameOrEmail
                    );
                });

        log.debug("Successfully loaded user: {} with role {}", user.getUsername(), user.getRole());
        return user;
    }
}
