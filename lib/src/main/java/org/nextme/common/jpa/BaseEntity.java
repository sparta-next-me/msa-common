package org.nextme.common.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Getter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseEntity extends JpaAudit {

    @CreatedBy
    @Column(updatable = false, name = "created_by", length = 50)
    private String createdBy;

    @LastModifiedBy
    @Column(name = "update_by", length = 50)
    private String updatedBy;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    @Column(name = "deleted_by", length = 50)
    private String deletedBy;

    @Column(name = "etc", columnDefinition = "TEXT")
    private String etc;

    public void markAsDeleted(String deleter) {
        this.deletedAt = LocalDateTime.now();
        this.deletedBy = deleter;
    }

    public boolean isDeleted() {
        return this.deletedAt != null;
    }
}