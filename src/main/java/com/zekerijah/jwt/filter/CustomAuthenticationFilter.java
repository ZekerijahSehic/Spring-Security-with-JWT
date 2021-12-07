package com.zekerijah.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // 10. We need to inject in this class, AuthenticationManager because we need to authenticate user
    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
    }

    // 9. UsernamePasswordAuthenticationFilter override methode
    // This method is call whenever user try to login, in this method we grab from req username and password then put
    // them in authenticationToken and then we call authenticationManager to authenticate user
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username: " + username );
        log.info("Username: " + password );
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return  authenticationManager.authenticate(authenticationToken);
    }

    // 9. UsernamePasswordAuthenticationFilter override methode
    // This method is call when login is successful and send access token or refresh token
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication ) throws IOException, ServletException {
        // 12. Spring Security User, with authentication.getPrincipal() we grab informations, getPrincipal() returning object
        // so because of that we need to cast it to (User), this infos we need for create JWT
        User user = (User)authentication.getPrincipal();

        // Dependency for jwt, we chosse HMAC256 byte algoritham and pass our secret, this alg will use to sigh the JWT
        // this way with "secret" is not good for production, for it use some encrypted decrypted vale
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

        // Now when we have algoritham we can create token, first token we need is access, then refresher token
        String access_token = JWT.create()
                // something uniqe for one user
                .withSubject(user.getUsername())
                // time expire
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 + 60 + 1000))
                // we can set "issuer" of token
                .withIssuer(request.getRequestURI().toString())
                // with this we pass roles of user in this token
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                // then we sign token with algoritham
                .sign(algorithm);

        String refresh_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 + 60 + 1000))
                .withIssuer(request.getRequestURI().toString())
                .sign(algorithm);

        response.setHeader("access_token", access_token);
        response.setHeader("refresh_token", refresh_token);
    }
}
