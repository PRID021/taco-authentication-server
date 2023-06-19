package com.example.authentication;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.authentication.models.TacoUser;
import com.example.authentication.repository.UserRepository;

@Configuration
public class DataConfig {
    @Bean
    public ApplicationRunner dataLoader(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            TacoUser userA = new TacoUser("user1", passwordEncoder.encode("1"),
                    "userA", "1234", "city", "state",
                    "zip", "1234567890", TacoUser.RoleType.USER);
            TacoUser userB = new TacoUser("user2", passwordEncoder.encode("1"),
                    "userB", "1234", "city", "state",
                    "zip", "1234567890", TacoUser.RoleType.ADMIN);
            userRepository.save(userA);
            userRepository.save(userB);

        };
    }
}
