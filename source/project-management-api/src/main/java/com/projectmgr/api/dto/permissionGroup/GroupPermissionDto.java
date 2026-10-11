package com.projectmgr.api.dto.permissionGroup;

import com.projectmgr.api.dto.ABasicAdminDto;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema
public class GroupPermissionDto extends ABasicAdminDto {
    @Schema(name = "name")
    private String name;
    @Schema(name = "ordering")
    private Integer ordering;
}
