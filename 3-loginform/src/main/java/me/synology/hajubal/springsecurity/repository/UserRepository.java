package me.synology.hajubal.springsecurity.repository;

import me.synology.hajubal.springsecurity.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    UserEntity findByUsername(String username);
}
