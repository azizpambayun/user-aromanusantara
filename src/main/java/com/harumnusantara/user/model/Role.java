package com.harumnusantara.user.model;

import lombok.Getter;

@Getter
public enum Role {
    USER("User"),
    ADMIN("Administrator"),
    MODERATOR("Moderator");

    private final String description;

    Role(String description) {
        this.description = description;
    }

    public boolean hasAdminPrivileges() {
        return this == ADMIN || this == MODERATOR;
    }

    public boolean isAdmin() {
        return this == ADMIN;
    }
}
