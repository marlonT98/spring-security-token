package com.app.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    //necesitamos dos cosas
    // 1.-una clave privada
    //2.-user generator <- un usuario generador del token

    //con estas dos propiedades garantizaremos la autenticidad de nuestro token
    //1
    @Value("${security.jwt.key.private}")
    private String privateKey;

    //2
    @Value("${security.jwt.user.generator}")
    private String userGenerator;

    //Meotod que se encargara de crear nuestro token
    //Authentication:de aqui extraeremos el usuario y las autorizaciones
    public String createToken(Authentication authentication) {


        Algorithm algorithm = Algorithm.HMAC256(this.privateKey);//encriptando con este algoritmo (algoritmo de incriptacion con su firma)

        String username = authentication.getPrincipal().toString();//extraemos el usuario autenticado

        //READ ,WRITE,DELETE<- tenemos que extraer las autorizaciones con una como por ello utilizamos stream
        String authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));//toma cada uno de esos permisos y los separa por comas

        //generando el token
        String jwtToken = JWT.create()
                .withIssuer(this.userGenerator)//este es el usuario que generara el token ( nuestro backend)
                .withSubject(username)//el sujeto a quien se le va a generar el token (osea el usuario que se esta autenticando)
                .withClaim("authorities", authorities)//las autorizaciones o permisos que tendra (read,create,delete)
                .withIssuedAt(new Date())//fecha en la que se generara el token
                .withExpiresAt(new Date(System.currentTimeMillis() + 1800000))//experizacion del token (el emomento en segundo + 30 minutos expresado en segundos) osea expira en 30 minutos
                .withJWTId(UUID.randomUUID().toString())//agregamos un id a nuestro identificador cualquiera
                .withNotBefore(new Date(System.currentTimeMillis()))//a partir de que momento este token se considerara valido (le estamos diciendo desde ahora )
                .sign(algorithm);//pasamos el afirma con su algoritmo de incriptacion

        return jwtToken;//por ultimo lo retornamos

    }

    //creamos un metodo que se encargara de validar nuestro token
    // este meotodo devolvera el jwt decodificado DecodedJWT
    public DecodedJWT validateToken(String token) {

        //cuando yo reciba el token
        //tendre un try-catch
        try {

            //algoritmo de incriptacion con la clave privada
            Algorithm algorithm = Algorithm.HMAC256(this.privateKey);

            //verificador del token
            JWTVerifier verifier = JWT.require(algorithm)//el algoritmo de incriptacion
                    .withIssuer(this.userGenerator)//el usuario que genero el token
                    .build();

            DecodedJWT decodedJWT = verifier.verify(token);

            return decodedJWT;


        } catch (JWTVerificationException exception) {//si se lanza el token es invalido
            throw new JWTVerificationException("token invalid , not authorized");

        }

    }

    //3.-metodo para extraer  el usuario que viene dentro del token
    public String extractUserName(DecodedJWT decodedJWT) {

        return decodedJWT.getSubject().toString();

    }

    //4.-extrae un clain especifico
    public Claim getSpecificClaim(DecodedJWT decodedJWT, String clainName) {


        return decodedJWT.getClaim(clainName);

    }

    //5.-extrae todos los claim
    public Map<String, Claim> returnAllClaim(DecodedJWT decodedJWT) {

        return decodedJWT.getClaims();

    }


}
