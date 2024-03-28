package it.cws.myecomapp.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController

public class AuthController {
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;
    private UserDetailsService userDetailsService;
    private AuthenticationManager authenticationManager;

    public AuthController(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, UserDetailsService userDetailsService, AuthenticationManager authenticationManager) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
    }
    @PostMapping("/auth/token")
    public ResponseEntity<Map<String,String>> jwtToken(String grantType,
                                                      String username,
                                                      String password,
                                                      boolean withRefrestToken,
                                                      String refreshTOken
    ){
        String subject=null;
        String scopes =null;

        if (grantType.equals("password")){
            Authentication  authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
            subject=authentication.getName();
             scopes = authentication.getAuthorities().
                    stream().map(aut -> aut.getAuthority())
                    .collect(Collectors.joining(" "));

        }else if(grantType.equals("refreshToken")){
            if (refreshTOken==null){
                return  new ResponseEntity<>(Map.of("ErrorMessage","RefreshToken Is Required"), HttpStatus.UNAUTHORIZED);
            }
            Jwt decodeJWT = null;
            try {
                decodeJWT = jwtDecoder.decode(refreshTOken);
            } catch (JwtException e) {
                return  new ResponseEntity<>(Map.of("ErrorMessage",e.getMessage()), HttpStatus.UNAUTHORIZED);
            }
            subject= decodeJWT.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
            scopes = authorities.stream().map(aut -> aut.getAuthority()).collect(Collectors.joining(" "));
            subject = userDetails.getUsername();


        }

        Instant instant= Instant.now();

        JwtClaimsSet jwtClaimsSet= JwtClaimsSet.builder()
                .subject(subject)
                .issuedAt(instant)
                .expiresAt(instant.plus(withRefrestToken?5:30, ChronoUnit.MINUTES))
                .issuer("Security-server")
                .claim("scopes",scopes)
                .build();
        Map<String,String> map= new HashMap<>();
        String jwtAccessToken= jwtEncoder
                .encode(JwtEncoderParameters.from(jwtClaimsSet))
                .getTokenValue();
        if (withRefrestToken){
            JwtClaimsSet jwtClaimsSet1= JwtClaimsSet
                    .builder()
                    .subject(subject)
                    .issuedAt(instant.plus(30,ChronoUnit.MINUTES))
                    .issuer("Security-Server")
                    .build();
            map.put("refreshTOken",jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet1)).getTokenValue());
        }



        map.put("accessToken",jwtAccessToken);

        return new ResponseEntity<>(map,HttpStatus.OK);
    }

}
