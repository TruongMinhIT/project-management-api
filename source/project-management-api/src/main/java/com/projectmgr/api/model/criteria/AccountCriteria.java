package com.projectmgr.api.model.criteria;

import com.projectmgr.api.model.Account;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.StringUtils;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Data
public class AccountCriteria implements Serializable {
    private static final long serialVersionUID = 1L;
    private Long id;
    private Integer role;
    private String username;
    private Integer status;
    private String email;
    private String fullName;
    private String phone;

    @Schema(hidden = true)
    public Specification<Account> getSpecification() {
        return new Specification<Account>() {
            private static final long serialVersionUID = 1L;

            @Override
            public Predicate toPredicate(Root<Account> root, CriteriaQuery<?> query, CriteriaBuilder cb) {
                List<Predicate> predicates = new ArrayList<>();

                if (getId() != null) {
                    predicates.add(cb.equal(root.get("id"), getId()));
                }
                if (getRole() != null) {
                    predicates.add(cb.equal(root.get("role"), getRole()));
                }
                if (getStatus() != null) {
                    predicates.add(cb.equal(root.get("status"), getStatus()));
                }
                if (StringUtils.hasLength(getUsername())) {
                    predicates.add(cb.like(cb.lower(root.get("username")), "%" + getUsername().toLowerCase() + "%"));
                }
                if (StringUtils.hasLength(getEmail())) {
                    predicates.add(cb.like(cb.lower(root.get("email")), "%" + getEmail().toLowerCase() + "%"));
                }
                if (StringUtils.hasLength(getFullName())) {
                    predicates.add(cb.like(cb.lower(root.get("fullName")), "%" + getFullName().toLowerCase() + "%"));
                }
                return cb.and(predicates.toArray(new Predicate[predicates.size()]));
            }
        };
    }
}
