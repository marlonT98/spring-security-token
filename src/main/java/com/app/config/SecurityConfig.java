package com.app.config;

import com.app.filter.JwtTokenValidator;
import com.app.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

//seguridad basica con estas tres anotaciones
@Configuration//le estamos diciendo que es una clase de configuracion
@EnableWebSecurity //habilitamos la seguirad web
@EnableMethodSecurity//nos permite hacer algunas configiraciones con ayuda de anotaciones de springSecurity
public class SecurityConfig {

    @Autowired
    private JwtUtils jwtUtils;

    //1.-security filter chain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {


        return httpSecurity
                .csrf(csrf -> csrf.disable())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(http -> {
                    //configuramos los endpoints publicos
                    http.requestMatchers(HttpMethod.POST, "/auth/**").permitAll();

                    //configurar los endpoints privados
                    http.requestMatchers(HttpMethod.POST, "/method/post").hasAnyRole("ADMIN","DEVELOPER");
                    http.requestMatchers(HttpMethod.PATCH, "/method/patch").hasAnyAuthority("REFACTOR");
                    http.requestMatchers(HttpMethod.GET, "/method/get").hasAnyAuthority("READ");


                    //configurar el resto de los endpoints - NO ESPECIFICACOS (son los que no estan ni en publicos ni privados)
                    // todos los endpoints necesitamos que yo este autenticado
                    http.anyRequest().denyAll();//rechaza todo lo que no se especifique
                    //http.anyRequest().authenticated();//aunque yo no especifique arribe pero si tengo las credeenciales correctas me deja pasar.
                })
                .addFilterBefore( new JwtTokenValidator( jwtUtils ) , BasicAuthenticationFilter.class)//agregemos el filtro antes que se ejecute el filtro de autenticacion
                .build();


    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity  httpSecurity  ) throws Exception {
//
//        return  httpSecurity
//                .csrf( csrf -> csrf.disable() )
//                .httpBasic(Customizer.withDefaults())
//                .sessionManagement( session->session.sessionCreationPolicy( SessionCreationPolicy.STATELESS) )
//                .build();
//
//    }

    @Bean
    public AuthenticationManager authenticationManager ( AuthenticationConfiguration authenticationConfiguration) throws Exception {

        return  authenticationConfiguration.getAuthenticationManager();

    }


    @Bean
    public AuthenticationProvider  authenticationProvider ( UserDetailsService userDetailsService  ){

        DaoAuthenticationProvider provider =  new DaoAuthenticationProvider();
        provider.setPasswordEncoder( passwordEncoder() );
        provider.setUserDetailsService( userDetailsService);

        return  provider;

    }

    @Bean
    public PasswordEncoder passwordEncoder( ){

        //solo para pruebas
        return new BCryptPasswordEncoder();

    }














}
