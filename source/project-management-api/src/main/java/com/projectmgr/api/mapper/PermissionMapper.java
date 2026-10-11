package com.projectmgr.api.mapper;

import com.projectmgr.api.dto.permission.PermissionDto;
import com.projectmgr.api.form.permission.CreatePermissionForm;
import com.projectmgr.api.model.Permission;
import org.mapstruct.*;

import java.util.List;

@Mapper(componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE,
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
public interface PermissionMapper {
    @Mapping(source = "name", target = "name")
    @Mapping(source = "description", target = "description")
    @Mapping(source = "action", target = "action")
    @Mapping(source = "showMenu", target = "showMenu")
    @Mapping(source = "permissionCode", target = "permissionCode")
    @BeanMapping(ignoreByDefault = true)
    @Named("fromCreatePermissionFormToEntity")
    Permission fromCreatePermissionFormToEntity(CreatePermissionForm createPermissionForm);

    @Mapping(source = "id", target = "id")
    @Mapping(source = "name", target = "name")
    @Mapping(source = "action", target = "action")
    @Mapping(source = "showMenu", target = "showMenu")
    @Mapping(source = "description", target = "description")
    @Mapping(source = "permissionCode", target = "permissionCode")
    @BeanMapping(ignoreByDefault = true)
    @Named("fromEntityToPermissionDto")
    PermissionDto fromEntityToPermissionDto(Permission permission);

    @IterableMapping(elementTargetType = PermissionDto.class, qualifiedByName = "fromEntityToPermissionDto")
    @Named("fromEntityToPermissionDtoList")
    List<PermissionDto> fromEntityToPermissionDtoList(List<Permission> permissions);
}
