package com.projectmgr.api.service.id;

import com.projectmgr.api.model.ReuseId;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.generator.BeforeExecutionGenerator;
import org.hibernate.generator.EventType;

import java.util.EnumSet;

public class IdGenerator implements BeforeExecutionGenerator {

    @Override
    public Object generate(SharedSessionContractImplementor session, Object owner, Object currentValue, EventType eventType) {
        if (owner instanceof ReuseId reuseId && reuseId.getReusedId() != null) {
            return reuseId.getReusedId();
        }
        return SnowFlakeIdService.getInstance().nextId();
    }

    @Override
    public EnumSet<EventType> getEventTypes() {
        return EnumSet.of(EventType.INSERT);
    }

    @Override
    public boolean allowAssignedIdentifiers() {
        return true;
    }

    public Long nextId() {
        return SnowFlakeIdService.getInstance().nextId();
    }
}
