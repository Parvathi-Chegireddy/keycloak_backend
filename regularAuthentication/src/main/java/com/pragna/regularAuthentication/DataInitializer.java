package com.pragna.regularAuthentication;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initRoles(RoleRepository roleRepository) {
        return args -> {

            if (roleRepository.findByName("ROLE_ADMIN") == null) {
                Role admin = new Role();
                admin.setName("ROLE_ADMIN");
                roleRepository.save(admin);
            }

            if (roleRepository.findByName("ROLE_USER") == null) {
                Role user = new Role();
                user.setName("ROLE_USER");
                roleRepository.save(user);
            }
        };
    }
}