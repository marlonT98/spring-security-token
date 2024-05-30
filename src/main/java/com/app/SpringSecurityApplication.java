package com.app;

import com.app.persistence.entity.PermissionEntity;
import com.app.persistence.entity.RoleEntity;
import com.app.persistence.entity.RoleEnum;
import com.app.persistence.entity.UserEntity;
import com.app.persistence.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

@SpringBootApplication
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

	@Bean
	CommandLineRunner init(UserRepository userRepository){

		return args -> {
			//1.- los permisoes
			PermissionEntity crearPermission = PermissionEntity.builder()
					.name("CREATE")
					.build();
			PermissionEntity readPermission = PermissionEntity.builder()
					.name("READ")
					.build();

			PermissionEntity updatePermission = PermissionEntity.builder()
					.name("UPDATE")
					.build();

			PermissionEntity deletePermission = PermissionEntity.builder()
					.name("DELETE")
					.build();
			PermissionEntity refactorPermission = PermissionEntity.builder()
					.name("REFACTOR")
					.build();

			//2.-SEGUNDO CREAMOS LOS ROLES
			RoleEntity roleAdmin = RoleEntity.builder()
					.roleEnum(RoleEnum.ADMIN)
					.permissionList(Set.of( crearPermission , readPermission , updatePermission , deletePermission))
					.build();

			RoleEntity rolUser = RoleEntity.builder()
					.roleEnum(RoleEnum.USER)
					.permissionList(Set.of(crearPermission,readPermission))
					.build();


			RoleEntity rolInvited = RoleEntity.builder()
					.roleEnum(RoleEnum.INVITED)
					.permissionList(Set.of(readPermission))
					.build();


			RoleEntity rolDeveloper = RoleEntity.builder()
					.roleEnum(RoleEnum.DEVELOPER)
					.permissionList(Set.of(crearPermission,readPermission,updatePermission,deletePermission ,refactorPermission))
					.build();

			//3.-TERCER PASO CREAMOS LOS USUARIOS
			UserEntity userSantiago = UserEntity.builder()
					.username("santiago")
					.password("$2a$10$HjLKOAG3gcBIFio7BSNgBuY8E9zPzDIaY0qxlD2rdCfDVzk/LSjfe")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked( true )//la cuenta no esta bloqueada
					.credentialNoExpired(true)
					.roles(Set.of(  roleAdmin ) )
					.build();

			UserEntity userDaniel = UserEntity.builder()
					.username("daniel")
					.password("$2a$10$HjLKOAG3gcBIFio7BSNgBuY8E9zPzDIaY0qxlD2rdCfDVzk/LSjfe")
					.isEnabled(true)//la cuenta esta activo
					.accountNoExpired(true)//la cuenta no ha expirado
					.accountNoLocked(true)//la cuenta no esta bloqueada
					.credentialNoExpired(true)//creedenciales no estan expiradas
					.roles(Set.of(rolUser))
					.build();

			UserEntity userAndrea = UserEntity.builder()
					.username("andrea")
					.password("$2a$10$HjLKOAG3gcBIFio7BSNgBuY8E9zPzDIaY0qxlD2rdCfDVzk/LSjfe")
					.isEnabled(true)//la cuenta esta activo
					.accountNoExpired(true)//la cuenta no ha expirado
					.accountNoLocked(true)//la cuenta no esta bloqueada
					.credentialNoExpired(true)//creedenciales no estan expiradas
					.roles(Set.of(rolInvited))
					.build();

			UserEntity userAnyi = UserEntity.builder()
					.username("anyi")
					.password("$2a$10$HjLKOAG3gcBIFio7BSNgBuY8E9zPzDIaY0qxlD2rdCfDVzk/LSjfe")
					.isEnabled(true)//la cuenta esta activo
					.accountNoExpired(true)//la cuenta no ha expirado
					.accountNoLocked(true)//la cuenta no esta bloqueada
					.credentialNoExpired(true)//creedenciales no estan expiradas
					.roles(Set.of(rolDeveloper))
					.build();

			//guardando en la base de datos
			userRepository.saveAll(List.of( userSantiago,userDaniel,  userAndrea ,userAnyi  ));



		};
	}

}
