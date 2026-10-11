package com.projectmgr.api.dto;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema
public class AccountForTokenDto {
    @JsonSerialize(using = LongToStringIfWebSerializer.class)
    @Schema(name = "id")
    private Long id;
    @Schema(name = "role")
    private Integer role;
    @Schema(name = "username")
    private String username;
    @Schema(name = "email")
    private String email;
    @Schema(name = "fullName")
    private String fullName;
    @Schema(name = "isSuperAdmin")
    private Boolean isSuperAdmin;
}
