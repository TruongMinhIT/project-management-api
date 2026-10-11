package com.projectmgr.api.validation.impl;

import com.projectmgr.api.constant.BaseConstant;
import com.projectmgr.api.validation.PhoneConstraint;
import org.apache.commons.lang3.StringUtils;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PhoneValidation implements ConstraintValidator<PhoneConstraint, String> {
    private boolean allowNull;

    @Override
    public void initialize(PhoneConstraint constraintAnnotation) {
        allowNull = constraintAnnotation.allowNull();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext constraintValidatorContext) {
        return StringUtils.isBlank(value) ? allowNull : StringUtils.isNotBlank(value) && value.matches(BaseConstant.PHONE_PATTERN);
    }
}
