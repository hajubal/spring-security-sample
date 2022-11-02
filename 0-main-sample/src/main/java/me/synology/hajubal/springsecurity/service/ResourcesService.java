package me.synology.hajubal.springsecurity.service;

import me.synology.hajubal.springsecurity.domain.entity.Resources;

import java.util.List;

public interface ResourcesService {

    Resources getResources(long id);

    List<Resources> getResources();

    void createResources(Resources Resources);

    void deleteResources(long id);
}