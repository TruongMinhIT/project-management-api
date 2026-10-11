package com.projectmgr.api.repository;

import com.projectmgr.api.model.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface PermissionRepository extends JpaRepository<Permission, Long>, JpaSpecificationExecutor<Permission> {
    Boolean existsByPermissionCode(String permissionCode);

    Boolean existsByPermissionCodeAndIdNot(String permissionCode, Long id);
}
