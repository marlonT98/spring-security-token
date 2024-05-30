package com.app.service;

import com.app.controller.dto.AuthCreateUserRequest;
import com.app.controller.dto.AuthResponse;
import com.app.controller.dto.AuthLoginRequest;
import com.app.persistence.entity.RoleEntity;
import com.app.persistence.entity.UserEntity;
import com.app.persistence.repository.RoleRepository;
import com.app.persistence.repository.UserRepository;
import com.app.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;


    //metodo que nos busca el usuario en la base de datos
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userEntity = userRepository.findUserEntityByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("El user " + username + "  no fue encontrado"));

        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        userEntity.getRoles()
                .forEach(role -> authorityList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name()))));


        userEntity.getRoles().stream()
                .flatMap(role -> role.getPermissionList().stream())
                .forEach(permissionEntity -> authorityList.add(new SimpleGrantedAuthority(permissionEntity.getName())));


        //con esto le estamos diciendo a spring security que busque los usuarios en bdd , que tome los permisos
        //roles, y los convierta a objetos que entiende spring security y devolvemos el usuario , pero un objeto
        //que entiende spring security
        //userEntity pasamos a User <-user es una clase de spring security
        return new User(
                userEntity.getUsername(),
                userEntity.getPassword(),
                userEntity.isEnabled(),
                userEntity.isAccountNoExpired(),
                userEntity.isCredentialNoExpired(),
                userEntity.isAccountNoLocked(),
                authorityList
        );


    }

    //metodo que nos permite hacer el login del usuario
    public AuthResponse loginUser(AuthLoginRequest authLoginRequest) {

        //aqui es donde generaremos el token de acceso

        //recuperamos el usuario
        String username = authLoginRequest.username();
        //recuperamos la contraseña
        String password = authLoginRequest.password();

        //si el usuario se autentico bien
        Authentication authentication = this.authenticate(username, password);

        //llamamos al holder y pasamos el objeto ya autenticado
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //generamos el token
        String accesToken = jwtUtils.createToken(authentication);

        //creando el authResponse y devolviendo
        AuthResponse authResponse = new AuthResponse(
                username,
                "User loged succesfuly",
                accesToken,
                true);

        return authResponse;

    }

    //Este metodo se encargara que las credenciales sean correctas
    //en este meotod recibo el usuario y el password
    public Authentication authenticate(String username, String password) {


        //yo tengo que buscar al usuario en la base de datos

        //buscame el usuario en la base de datos y  me dices si existe
        UserDetails userDetails = this.loadUserByUsername(username);

        //si el usuario existe
        if (userDetails == null) {
            //no existe
            throw new BadCredentialsException("Invalid username or password");
        }

        //necesitamos validar si la conraeña es correcta (necesitsmos inyectar el passwordEncoder)
        //si estos dos no son iguales
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {

            //votamos un error
            throw new BadCredentialsException("Invalid  password");

        }

        //si el usuario existe y la contraseña es correcta devolvemos
        //el usuario , contraseña y los persmisos
        return new UsernamePasswordAuthenticationToken(username, userDetails.getPassword(), userDetails.getAuthorities());


    }

    //metodo para crear un usuario
    public AuthResponse createUser(AuthCreateUserRequest authCreateUserRequest) {
        //aqui registraremos el usuario en la base de datos

        //obtenemos el usuario y la contraseña
        String username = authCreateUserRequest.username();
        String password = authCreateUserRequest.password();
        //obtenemos la lista de los roles
        List<String> roleRequest = authCreateUserRequest.roleRequest().roleListName();


        //buscara solo los roles que envio aqui
        //nos envia una lista pero estamos convirtiendo al un set(el set no permite valores repetidos)
        Set<RoleEntity> roleEntitiesSet = roleRepository.findRoleEntitiesByRoleEnumIn(roleRequest).stream().collect(Collectors.toSet());

        //validar los roles que estan enviando sean los mismos que estan en la tabla
        if (roleEntitiesSet.isEmpty()) {//si esta vacio no podemos crear el usuario

            throw new IllegalArgumentException("the roles specified does not exist.");


        }

        //si hay como minimo hay un rol continuamos
        //contruimos el usuario
        UserEntity userEntity = UserEntity.builder()
                .username( username)
                .password( passwordEncoder.encode( password ) )//nuestro password lo tenemos que encriptar
                .roles( roleEntitiesSet )
                .isEnabled( true)//esta activo
                .accountNoLocked( true )//la cuenta no esta bloqueada
                .accountNoExpired( true )//la cuenta no esta expirada
                .credentialNoExpired( true  )//las credenciales no estan expiradas
                .build();
        //cuando el crea al usuario , el me devuelve a ese usuario
        UserEntity userCreated =   userRepository.save( userEntity );//guardamos en la base de datos

        //creamos la lista que sera seteada con los permisos que tendra este usuario
        ArrayList< SimpleGrantedAuthority >authorityList = new ArrayList<>();
        //seteamos el rol
        userCreated.getRoles().forEach( role -> authorityList.add( new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name())) ));
        //setemos los persmisos
        userCreated.getRoles()
                .stream()
                .flatMap(role-> role.getPermissionList().stream())
                .forEach( permission -> authorityList.add( new SimpleGrantedAuthority( permission.getName() ) ));

        //es le momento de dale los accesos
        Authentication authentication = new UsernamePasswordAuthenticationToken(userCreated.getUsername() , userCreated.getPassword() ,authorityList);
        //generamos el token
        String accesToken = jwtUtils.createToken( authentication );
        //damos la respuesta
        AuthResponse authResponse = new AuthResponse(
                userCreated.getUsername() ,
                "User created successfully",
                accesToken,
                true  );


        return authResponse;


    }


}
