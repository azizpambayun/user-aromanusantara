package com.harumnusantara.user.config;

import com.harumnusantara.user.model.Role;
import com.harumnusantara.user.model.User;
import com.harumnusantara.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Slf4j
@RequiredArgsConstructor
public class DataInitializer implements ApplicationRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    @Override
    public void run(ApplicationArguments args) throws Exception {
        log.info("Starting data initialization...");

        initializeDefaultUsers();

        log.info("Data initialization completed");
    }

    private void initializeDefaultUsers() {
        if (userRepository.count() > 0) {
            log.info("User already exists, skipping initialization");
            return;
        }

        log.info("Initializing default users");

        createAdminUser();
        createRegularUser();
        logInitializationSummary();

        log.info("Default users created successfully!");

    }

    private void createAdminUser() {
        User admin = new User(
                "adminilham",
                "adminilham@admin.com",
                passwordEncoder.encode("adminilham123"),
                "admin ilham",
                Role.ADMIN
        );

        User savedAdmin = userRepository.save(admin);
        log.info("Admin user created: {} (ID:{})", savedAdmin.getUsername(), savedAdmin.getId());
        log.info("Admin login credentials -> Username: adminilham, Password: adminilham123");
    }

    private void createRegularUser() {
        User user1 = new User(
                "ilhamkurniawan",
                "ilhamkurniawan@user.com",
                passwordEncoder.encode("ilhamkurniawan123"),
                "ilham kurniawan",
                Role.USER
        );

        User savedUser1 = userRepository.save(user1);
        log.info("Regular user created: {} (ID:{})", savedUser1.getUsername(), savedUser1.getId());

        User user2 = new User(
                "farrelhoreg",
                "farrelhoreg@user.com",
                passwordEncoder.encode("farrelhoreg123"),
                "farrel horeg",
                Role.USER
        );

        User savedUser2 = userRepository.save(user2);
        log.info("Regular user created: {} (ID:{})", savedUser2.getUsername(), savedUser2.getId());

        log.info("Test user login credentials -> " +
                "Username: ilhamkurniawan/farrelhoreg, Password: ilhamkurniawan123/farrelhoreg123");


    }

    private void logInitializationSummary() {
        long totalUsers = userRepository.count();
        List<User> allUsers = userRepository.findAll();

        long adminCount = allUsers.stream()
                .filter(user -> user.getRole() == Role.ADMIN)
                .count();
        long userCount = allUsers.stream()
                .filter(user -> user.getRole() == Role.USER)
                .count();
        long moderatorCount = allUsers.stream()
                .filter(user -> user.getRole() == Role.MODERATOR)
                .count();

        log.info("\n" +
                        "=== Data Initialization Summary ===\n" +
                        "Total Users: {}\n" +
                        "- Admins: {}\n" +
                        "- Moderators: {}\n" +
                        "- Regular Users: {}\n" +
                        "===================================",
                totalUsers, adminCount, moderatorCount, userCount
        );

        log.info("\n" +
                "=== Testing Credentials ===\n" +
                "Admin Login:\n" +
                "  Username: adminilham\n" +
                "  Password: adminilham123\n" +
                "  \n" +
                "Regular User Login:\n" +
                "  Username: ilhamkurniawan\n" +
                "  Password: ilhamkurniawan123\n" +
                "  Username: farrelhoreg\n" +
                "  Password: farrelhoreg123\n" +
                "=========================="
        );
    }

}
