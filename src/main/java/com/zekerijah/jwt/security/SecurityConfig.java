package com.zekerijah.jwt.security;

import com.zekerijah.jwt.filter.CustomAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 3. Provided by Spring Security, we need to create two beans in our Application and tell Spring how we want to load
    // users and create bean for password encoder
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // 1. WebSecurityConfigurerAdapter override methode
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    // 2. WebSecurityConfigurerAdapter override methode
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // disable cross site request forgery
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests().anyRequest().permitAll();
        // create filter for login ( new package filet )...
        // we need parameter for CustomAuthenticationFilter() which is AuthenticationManager
        http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean()));

    }

    // 11. AuthenticationManager is inside WebSecurityConfigurerAdapter and we can pass it in methode above
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        // we want call bean from class which we extends, with word super we refer to class which we extends
        return super.authenticationManagerBean();
    }
}
