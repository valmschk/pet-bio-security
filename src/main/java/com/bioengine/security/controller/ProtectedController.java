package com.bioengine.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/protected")
public class ProtectedController {

    @GetMapping("/profile")
    public Map<String, String> getProfile(Authentication authentication) {
        return Map.of(
                "message", "This is a protected endpoint!",
                "username", authentication.getName(),
                "role", authentication.getAuthorities().iterator().next().getAuthority()
        );
    }

    @GetMapping("/admin")
    public Map<String, String> getAdminData() {
        return Map.of("message", "Secret admin data");
    }
}