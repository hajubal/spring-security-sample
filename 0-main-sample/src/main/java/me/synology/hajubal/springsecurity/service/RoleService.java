package me.synology.hajubal.springsecurity.service;

import me.synology.hajubal.springsecurity.domain.entity.Role;

import java.util.List;

public interface RoleService {

    Role getRole(long id);

    List<Role> getRoles();

    void createRole(Role role);

    void deleteRole(long id);
}