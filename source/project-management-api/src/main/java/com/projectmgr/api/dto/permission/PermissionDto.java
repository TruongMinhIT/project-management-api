package com.projectmgr.api.dto.permission;

import com.projectmgr.api.dto.ABasicAdminDto;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema
public class PermissionDto extends ABasicAdminDto {
    @Schema(name = "name")
    private String name;
    @Schema(name = "action")
    private String action;
    @Schema(name = "showMenu")
    private Boolean showMenu;
    @Schema(name = "description")
    private String description;
    @Schema(name = "permissionCode")
    private String permissionCode;
    private String settings;
}
