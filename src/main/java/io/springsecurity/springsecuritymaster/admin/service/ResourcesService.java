package io.springsecurity.springsecuritymaster.admin.service;

import io.springsecurity.springsecuritymaster.domain.entity.Resources;

import java.util.List;

public interface ResourcesService {
    Resources getResources(long id);

    List<Resources> getResources();

    void createResources(Resources Resources);

    void deleteResources(long id);
}
