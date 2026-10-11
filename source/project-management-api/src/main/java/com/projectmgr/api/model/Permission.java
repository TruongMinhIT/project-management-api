package com.projectmgr.api.model;

import com.projectmgr.api.constant.DatabaseConstant;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.Table;

@Entity
@Table(name = DatabaseConstant.PREFIX_TABLE + "permission")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
public class Permission extends Auditable<String> {
    @Column(name = "name")
    private String name;
    @Column(name = "action")
    private String action;
    @Column(name = "show_menu")
    private Boolean showMenu;
    private String description;
    @Column(name = "permission_code", unique = true)
    private String permissionCode;
}
