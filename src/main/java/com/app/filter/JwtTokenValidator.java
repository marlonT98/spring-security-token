package com.app.filter;

import com.app.util.JwtUtils;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;


public class JwtTokenValidator extends OncePerRequestFilter {



    private JwtUtils jwtUtils;

    public JwtTokenValidator(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    //ejecutara este filtro por cada request:
    //es decir yo hago una peticion se ejecuta este filtro,  con esto garantizamos
    //que se ejecuta la validacion del token
    //se agrega la notacion notNull
    @Override
    protected void doFilterInternal(
         @NotNull HttpServletRequest request,
         @NotNull   HttpServletResponse response,
         @NotNull    FilterChain filterChain) throws ServletException, IOException {

        //obten el header que biene de este request
        String jwtToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        //validamos
        if ( jwtToken != null){//si tiene el token
            //validando el token recuerda que el token se envia con el Bearer opoiroerasajdiajh
            //tengo que tomar despues del bearer
            jwtToken = jwtToken.substring(7);//extrae el string a partir del indice 7
             DecodedJWT decodedJWT =  jwtUtils.validateToken( jwtToken );//si nos devuelve es valido

            //concedemos la autorizacion de acceso
            //necesitamos el usuario
            String username = jwtUtils.extractUserName( decodedJWT);
            //recuperamos las persmisos que tiene el usuario
            String stringAuthorities = jwtUtils.getSpecificClaim( decodedJWT , "authorities" ).asString();


            //seteamos en el security contex holder
            //en el principal seria el usuario
            //las authorities son los permisos que tiene

            //nosotros los permisos lo tenemos como string pero lo necesitamos a grantedAuthorities
            //esto porque spring boot security maneja los permisos como grantedAuthorities

            //commaSeparatedStringToAuthorityList: dame los permisos seprados con comas (read,write,delete)
            // y yo te los convierto a una lista de permisos
            Collection<? extends GrantedAuthority > authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(stringAuthorities);

            //========seteamos el usuario en el contexto de spring security=============
            //estoy extrayendo el contexto de spring security
            SecurityContext context = SecurityContextHolder.getContext();

            //estoy declarando el objeto authentication para insertar en el context holder
            //username, contraseña no por seguridad y las authorities
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username ,
                    null ,
                    authorities );
            context.setAuthentication( authentication );
            SecurityContextHolder.setContext( context );



        }
        //si no viene lo rechazamos
        filterChain.doFilter(request ,response);



    }

}
