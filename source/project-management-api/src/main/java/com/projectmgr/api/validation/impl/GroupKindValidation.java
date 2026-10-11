package com.projectmgr.api.validation.impl;

import com.projectmgr.api.constant.BaseConstant;
import com.projectmgr.api.validation.GroupKind;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.Objects;

public class GroupKindValidation implements ConstraintValidator<GroupKind, Integer> {
    private boolean allowNull;

    @Override
    public void initialize(GroupKind constraintAnnotation) {
        allowNull = constraintAnnotation.allowNull();
    }

    @Override
    public boolean isValid(Integer value, ConstraintValidatorContext constraintValidatorContext) {
        if (value == null && allowNull) {
            return true;
        }
        return Objects.equals(value, BaseConstant.GROUP_KIND_ADMIN);
    }
}