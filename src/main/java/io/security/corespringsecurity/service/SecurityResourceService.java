package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.repository.ResourcesRepository;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;


public class SecurityResourceService {

    private ResourcesRepository repository;

    public SecurityResourceService(ResourcesRepository repository) {
        this.repository = repository;
    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();

        List<Resources> resourcesList = repository.findAllResources();

        resourcesList.forEach(re -> {
            List<ConfigAttribute> configAttributeList = new ArrayList<>();

            re.getRoleSet().stream()
                    .map(Role::getRoleName)
                    .map(SecurityConfig::new)
                    .forEach(configAttributeList::add);

            RequestMatcher requestMatcher = new AntPathRequestMatcher(re.getResourceName());

            result.put(requestMatcher, configAttributeList);
        });

        return result;
    }
}
