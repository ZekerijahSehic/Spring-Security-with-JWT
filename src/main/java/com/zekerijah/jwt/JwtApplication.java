package com.zekerijah.jwt;

import com.zekerijah.jwt.model.Role;
import com.zekerijah.jwt.model.User;
import com.zekerijah.jwt.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtApplication.class, args);
    }

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService) {

        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new User(null, "Jon Doe", "jond", "jond1234", new ArrayList<>()));
            userService.saveUser(new User(null, "Jane Doe", "djane", "djane1234", new ArrayList<>()));
            userService.saveUser(new User(null, "Li Mun", "kinez", "kinez1234", new ArrayList<>()));
            userService.saveUser(new User(null, "Arnold Schwarzenegger", "terminator", "terminator1234", new ArrayList<>()));

            userService.addRoleToUser("jond", "ROLE_USER");
            userService.addRoleToUser("djane", "ROLE_MANAGER");
            userService.addRoleToUser("kinez", "ROLE_ADMIN");
            userService.addRoleToUser("terminator", "ROLE_MANAGER");
            userService.addRoleToUser("terminator", "ROLE_ADMIN");
            userService.addRoleToUser("terminator", "ROLE_SUPER_ADMIN");
        };
    }

}
