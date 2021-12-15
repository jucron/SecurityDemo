package io.getarrays.userservice.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

//todo 6: Create CustomAuthenticationFilter and override attemptAuthentication and successfulAuthentication
// This class is to give the user a token once they login successfully
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter (AuthenticationManager authenticationManager) {
        this.authenticationManager=authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username is: {}", username); log.info("Password is {}", password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override //This is called if attemptAuthentication is successful
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        //Attention for this next 'User' which is the one from Spring security:
        User user = (User) authResult.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes()); //'secret' would be encrypted somewhere and stored safely
        String access_token = JWT.create()
                .withSubject(user.getUsername()) //Should choose something unique that identifies (in this app usernames are uniques)
                .withExpiresAt(new Date(System.currentTimeMillis() +10*60*1000)) // Access Token (Bearer) will expire in 10 minutes
                .withIssuer(request.getRequestURL().toString()) //Company name or author of this
                .withClaim("roles", user.getAuthorities().stream() //Roles of this specific user
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm); //must sign the Token with the algorithm created
        String refresh_token = JWT.create()
                .withSubject(user.getUsername()) //Should choose something unique that identifies (in this app usernames are uniques)
                .withExpiresAt(new Date(System.currentTimeMillis() +30*60*1000)) // Refresh Token (creates new AccessTokens) will expire in 30 minutes
                .withIssuer(request.getRequestURL().toString()) //Company name or author of this
                .sign(algorithm); //must sign the Token with the algorithm created
        // Response to the Front-end, giving them headers
//        response.setHeader("access_token",access_token);
//        response.setHeader("refresh_token",refresh_token);
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token",access_token);
        tokens.put("refresh_token",refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }
}
