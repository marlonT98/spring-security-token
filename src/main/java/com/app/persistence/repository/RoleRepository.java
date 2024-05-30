package com.app.persistence.repository;


import com.app.persistence.entity.RoleEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RoleRepository  extends CrudRepository<RoleEntity , Long> {

    //crearemos un query method que nos devolvera los roles
    //con esto me traera solo los que existen
    List< RoleEntity> findRoleEntitiesByRoleEnumIn( List<String> roleNames  );


}
