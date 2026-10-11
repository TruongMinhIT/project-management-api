package com.projectmgr.api.dto.account;

import com.projectmgr.api.dto.ABasicAdminDto;
import com.projectmgr.api.dto.group.GroupDto;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema
public class AccountDto extends ABasicAdminDto {
    @Schema(name = "role")
    private Integer role;
    @Schema(name = "username")
    private String username;
    @Schema(name = "phone")
    private String phone;
    @Schema(name = "email")
    private String email;
    @Schema(name = "fullName")
    private String fullName;
    @Schema(name = "group")
    private GroupDto group;
    @Schema(name = "avatarPath")
    private String avatarPath;
    @Schema(name = "isSuperAdmin")
    private Boolean isSuperAdmin;
    @Schema(name = "isSuperAdmin")
    private Boolean isMfa;
}
