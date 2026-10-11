package com.projectmgr.api.component;

import com.projectmgr.api.constant.BaseConstant;
import com.projectmgr.api.service.impl.UserServiceImpl;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class OAuth2FeignRequestInterceptor implements RequestInterceptor { // cấu hình cho các cuộc gọi đến các service khác
    @Autowired
    private UserServiceImpl userService;

    @Override
    public void apply(RequestTemplate template) {
        String token = userService.getCurrentToken();
        if (token != null) {
            // never log the token itself: it is a live credential
            log.debug("Forwarding bearer token in {} to {}", BaseConstant.AUTHORIZATION_HEADER, template.url());
            template.header(BaseConstant.AUTHORIZATION_HEADER, "Bearer " + token);
        }
    }
}
