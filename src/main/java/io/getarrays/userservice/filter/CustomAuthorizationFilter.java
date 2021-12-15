package io.getarrays.userservice.filter;

//todo 7: Create an authorizationFilter in order to filter requests and allow access accordingly

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

//todo 8: Create CustomAuthorizationFilter, extends OncePerRequestFilter and override doFilterInternal
// This class verifies the token sent from user and allow them to the application

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Override //This intercepts any requests and customize authorizations
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // We need to clear the path for the standard login first
        if (request.getServletPath().equals("/api/login") ||
                request.getServletPath().equals("/api/token/refresh")) {
            filterChain.doFilter(request, response); //this let the request goes through
        } else {
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) { //This must be expected and implemented in the frontend
                try {
                    String token = authorizationHeader.substring("Bearer ".length());
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes()); //Use the same secret as signing (Authenticating) user.
                    //JWTVerifier assert Token and Signatures
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = verifier.verify(token);

                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class); //Variable name in User Class

                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    stream(roles).forEach(role -> {
                        authorities.add(new SimpleGrantedAuthority(role));
                    });
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username,null,authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken); //Set this user in security context Holder
                    filterChain.doFilter(request, response);
                } catch (Exception exception) {
                    log.error("Error login in: {}",exception.getMessage());
                    response.setHeader("error", exception.getMessage());
//                    response.sendError(FORBIDDEN.value()); //Option 1: send a http status error back
                    //Option 2: Send a JSON with the error embedded
                    response.setStatus(FORBIDDEN.value());
                    Map<String, String> error = new HashMap<>();
                    error.put("error_message",exception.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }
            } else {
                filterChain.doFilter(request, response); //just let the request continue
            }
        }
    }
}
