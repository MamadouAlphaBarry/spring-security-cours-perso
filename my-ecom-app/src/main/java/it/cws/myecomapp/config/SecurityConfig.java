package it.cws.myecomapp.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {
private  RsaKeysConfig rsaKeysConfig;
private BCryptPasswordEncoder bCryptPasswordEncoder;
  @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
       return  httpSecurity
               .csrf(csrf->csrf.disable())
               //.authorizeHttpRequests(aut->aut.requestMatchers("/token/*").permitAll())
               .authorizeHttpRequests(aut->aut.requestMatchers("/auth/*").permitAll())
               .authorizeHttpRequests(aut->aut.anyRequest().authenticated())
               .sessionManagement(ssm->ssm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
               .oauth2ResourceServer(oat->oat.jwt(Customizer.withDefaults()))
               .httpBasic(Customizer.withDefaults())
               .build();

    }
  @Bean
    public UserDetailsService inMemoryUserDetailsManager(){
     return  new InMemoryUserDetailsManager(
             User.withUsername("user").password(bCryptPasswordEncoder.encode("1234")).authorities("USER").build(),
             User.withUsername("admin").password(bCryptPasswordEncoder.encode("1234")).authorities("ADMIN","USER","MANAGER").build()

     );
    }
    @Bean
    JwtEncoder encoder(){
        JWK jwk=  new RSAKey.Builder(rsaKeysConfig.publicKey()).privateKey(rsaKeysConfig.privateKey()).build();
        JWKSource<SecurityContext> jwkSource= new ImmutableJWKSet<>(new JWKSet(jwk));
      return new NimbusJwtEncoder(jwkSource);
    }
    @Bean
    JwtDecoder decoder(){
      return  NimbusJwtDecoder.withPublicKey(rsaKeysConfig.publicKey()).build() ;
    }
   @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService){
      var authProvider= new DaoAuthenticationProvider();
      authProvider.setPasswordEncoder(bCryptPasswordEncoder);
      authProvider.setUserDetailsService(userDetailsService);
      return  new ProviderManager(authProvider);

    }

}
