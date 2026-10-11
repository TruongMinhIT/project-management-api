package com.projectmgr.api.model.criteria;

import com.projectmgr.api.model.Group;
import com.projectmgr.api.model.Permission;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.springframework.data.jpa.domain.Specification;

import jakarta.persistence.criteria.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Data
public class PermissionCriteria implements Serializable {
    private Integer groupKind;

    @Schema(hidden = true)
    public Specification<Permission> getSpecification() {
        return new Specification<Permission>() {
            private static final long serialVersionUID = 1L;

            @Override
            public Predicate toPredicate(Root<Permission> root, CriteriaQuery<?> query, CriteriaBuilder cb) {
                List<Predicate> predicates = new ArrayList<>();
                if (getGroupKind() != null) {
                    Join<Permission, Group> groupJoin = root.join("groups", JoinType.INNER);
                    predicates.add(cb.equal(groupJoin.get("kind"), groupKind));
                }
                query.distinct(true);
                return cb.and(predicates.toArray(new Predicate[predicates.size()]));
            }
        };
    }
}
