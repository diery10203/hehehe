Entity
Apartment
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.math.BigDecimal;

@Entity
@Table(name = "apartments")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Apartment {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "apartment_number", nullable = false)
    private String apartmentNumber;
    
    @Column(nullable = false)
    private Double area;
    
    @Column(nullable = false, precision = 19, scale = 2)
    private BigDecimal price;
    
    @Column(nullable = false)
    private String status;
    
    @ManyToOne
    @JoinColumn(name = "building_id", nullable = false)
    private Building building;
}

Building
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "buildings")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Building {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private String name;
    
    @Column(nullable = false)
    private String address;
    
    @OneToMany(mappedBy = "building", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Apartment> apartments = new ArrayList<>();
}

User
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.Collections;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "first_name", nullable = false)
    private String firstName;
    
    @Column(name = "last_name", nullable = false)
    private String lastName;
    
    @Column(unique = true, nullable = false)
    private String username;
    
    @Column(nullable = false)
    private String password;
    
    @Column(nullable = false)
    private String role = "CUSTOMER";
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role));
    }
    
    @Override
    public boolean isAccountNonExpired() { return true; }
    @Override
    public boolean isAccountNonLocked() { return true; }
    @Override
    public boolean isCredentialsNonExpired() { return true; }
    @Override
    public boolean isEnabled() { return true; }
}

Repository
ApartmentRepository
import com.ontap.entity.Apartment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ApartmentRepository extends JpaRepository<Apartment, Long> {
    List<Apartment> findByApartmentNumberContainingIgnoreCase(String number);
    List<Apartment> findByBuildingId(Long buildingId);
}

BuildingRepository
package com.ontap.repository;

import com.ontap.entity.Building;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BuildingRepository extends JpaRepository<Building, Long> {
}

UserRepository
package com.ontap.repository;

import com.ontap.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}


Service
ApartmentService
package com.ontap.service;

import com.ontap.entity.Apartment;
import java.util.List;

public interface ApartmentService {
    List<Apartment> findAll();
    Apartment findById(Long id);
    List<Apartment> searchByNumber(String keyword);
    Apartment save(Apartment apartment);
    void deleteById(Long id);
}

ApartmentServiceImpl

package com.ontap.service.impl;

import com.ontap.entity.Apartment;
import com.ontap.repository.ApartmentRepository;
import com.ontap.service.ApartmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class ApartmentServiceImpl implements ApartmentService {
    
    @Autowired
    private ApartmentRepository repository;
    
    @Override
    public List<Apartment> findAll() {
        return repository.findAll();
    }
    
    @Override
    public Apartment findById(Long id) {
        return repository.findById(id).orElse(null);
    }
    
    @Override
    public List<Apartment> searchByNumber(String keyword) {
        if (keyword == null || keyword.trim().isEmpty()) {
            return repository.findAll();
        }
        return repository.findByApartmentNumberContainingIgnoreCase(keyword.trim());
    }
    
    @Override
    public Apartment save(Apartment apartment) {
        return repository.save(apartment);
    }
    
    @Override
    public void deleteById(Long id) {
        repository.deleteById(id);
    }
}

Controller
ApartmentController
package com.ontap.controller;

import com.ontap.entity.Apartment;
import com.ontap.repository.BuildingRepository;
import com.ontap.service.ApartmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/apartment")
public class ApartmentController {
    
    @Autowired
    private ApartmentService apartmentService;
    
    @Autowired
    private BuildingRepository buildingRepository;
    
    @GetMapping
    public String list(Model model) {
        model.addAttribute("apartments", apartmentService.findAll());
        return "apartment/list";
    }
    
    @GetMapping("/{id}")
    public String view(@PathVariable Long id, Model model) {
        Apartment apartment = apartmentService.findById(id);
        if (apartment == null) return "redirect:/apartment";
        model.addAttribute("apartment", apartment);
        return "apartment/detail";
    }
    
    @GetMapping("/new")
    public String form(Model model) {
        model.addAttribute("apartment", new Apartment());
        model.addAttribute("buildings", buildingRepository.findAll());
        return "apartment/form";
    }
    
    @GetMapping("/edit/{id}")
    public String edit(@PathVariable Long id, Model model) {
        Apartment apartment = apartmentService.findById(id);
        if (apartment == null) return "redirect:/apartment";
        model.addAttribute("apartment", apartment);
        model.addAttribute("buildings", buildingRepository.findAll());
        return "apartment/form";
    }
    
    @PostMapping("/save")
    public String save(@ModelAttribute Apartment apartment, RedirectAttributes ra) {
        apartmentService.save(apartment);
        ra.addFlashAttribute("successMessage", "Lưu thành công!");
        return "redirect:/apartment";
    }
    
    @GetMapping("/delete/{id}")
    public String delete(@PathVariable Long id, RedirectAttributes ra) {
        apartmentService.deleteById(id);
        ra.addFlashAttribute("successMessage", "Xóa thành công!");
        return "redirect:/apartment";
    }
    
    @GetMapping("/search")
    public String search(@RequestParam(required = false) String keyword, Model model) {
        model.addAttribute("apartments", apartmentService.searchByNumber(keyword));
        model.addAttribute("keyword", keyword);
        return "apartment/list";
    }
}

AuthController
package com.ontap.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {
    
    @GetMapping("/login")
    public String login(@RequestParam(required = false) String error, Model model) {
        if (error != null) model.addAttribute("errorMessage", "Sai tên đăng nhập hoặc mật khẩu!");
        return "auth/login";
    }
}

HomeController
package com.ontap.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
    
    @GetMapping("/")
    public String home(Authentication auth) {
        if (auth != null && auth.isAuthenticated()) {
            return "redirect:/apartment";
        }
        return "index";
    }
}

Config
SecurityConfig
package com.ontap.config;

import com.ontap.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Autowired
    private UserRepository userRepository;
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }
    
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/", "/login").permitAll()
                .requestMatchers("/apartment/new", "/apartment/edit/**", "/apartment/save", "/apartment/delete/**").hasRole("ADMIN")
                .requestMatchers("/apartment/**").hasAnyRole("ADMIN", "CUSTOMER")
                .anyRequest().authenticated()
            )
            .authenticationProvider(authenticationProvider())
            .formLogin(form -> form.loginPage("/login").defaultSuccessUrl("/apartment", true))
            .logout(logout -> logout.logoutUrl("/logout").logoutSuccessUrl("/login"));
        return http.build();
    }
}

Templates
apartment
detail.html

<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/extras/spring-security">
<head>
    <meta charset="UTF-8">
    <title>Chi tiết Căn hộ</title>
</head>
<body>
    <h1>Chi tiết Căn hộ</h1>
    
    <div>
        <p><strong>ID:</strong> <span th:text="${apartment.id}"></span></p>
        <p><strong>Số căn hộ:</strong> <span th:text="${apartment.apartmentNumber}"></span></p>
        <p><strong>Diện tích:</strong> <span th:text="${apartment.area}"></span> m²</p>
        <p><strong>Giá:</strong> <span th:text="${apartment.price}"></span></p>
        <p><strong>Trạng thái:</strong> <span th:text="${apartment.status}"></span></p>
        <p><strong>Tòa nhà:</strong> <span th:text="${apartment.building != null ? apartment.building.name : 'N/A'}"></span></p>
        <p th:if="${apartment.building != null}"><strong>Địa chỉ:</strong> <span th:text="${apartment.building.address}"></span></p>
    </div>
    
    <div>
        <a sec:authorize="hasRole('ADMIN')" th:href="@{/apartment/edit/{id}(id=${apartment.id})}">Sửa</a>
        <a href="/apartment">Quay lại</a>
    </div>
</body>
</html>

form.hmtl
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title th:text="${apartment.id == null ? 'Tạo Căn hộ' : 'Sửa Căn hộ'}">Form Căn hộ</title>
</head>
<body>
    <h1 th:text="${apartment.id == null ? 'Tạo Căn hộ mới' : 'Sửa Căn hộ'}">Form</h1>
    
    <form th:action="@{/apartment/save}" th:object="${apartment}" method="post">
        <input type="hidden" th:field="*{id}">
        
        <div>
            <label>Số căn hộ:</label>
            <input type="text" th:field="*{apartmentNumber}" required>
        </div>
        
        <div>
            <label>Diện tích (m²):</label>
            <input type="number" th:field="*{area}" step="0.01" required>
        </div>
        
        <div>
            <label>Giá:</label>
            <input type="number" th:field="*{price}" step="0.01" required>
        </div>
        
        <div>
            <label>Trạng thái:</label>
            <select th:field="*{status}">
                <option value="AVAILABLE">AVAILABLE</option>
                <option value="RENTED">RENTED</option>
                <option value="SOLD">SOLD</option>
            </select>
        </div>
        
        <div>
            <label>Tòa nhà:</label>
            <select th:field="*{building.id}" required>
                <option value="">-- Chọn tòa nhà --</option>
                <option th:each="building : ${buildings}" 
                        th:value="${building.id}" 
                        th:text="${building.name}"></option>
            </select>
        </div>
        
        <button type="submit">Lưu</button>
        <a href="/apartment">Hủy</a>
    </form>
</body>
</html>

list.html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/extras/spring-security">
<head>
    <meta charset="UTF-8">
    <title>Danh sách Căn hộ</title>
</head>
<body>
    <h1>Danh sách Căn hộ</h1>
    
    <div th:if="${successMessage}" th:text="${successMessage}"></div>
    <div th:if="${errorMessage}" th:text="${errorMessage}"></div>
    
    <div>
        <a sec:authorize="hasRole('ADMIN')" href="/apartment/new">Tạo Căn hộ mới</a>
        <form th:action="@{/apartment/search}" method="get" style="display:inline;">
            <input type="text" name="keyword" th:value="${keyword}" placeholder="Tìm kiếm số căn hộ...">
            <button type="submit">Tìm</button>
        </form>
    </div>
    
    <table border="1">
        <tr>
            <th>ID</th>
            <th>Số căn hộ</th>
            <th>Diện tích (m²)</th>
            <th>Giá</th>
            <th>Trạng thái</th>
            <th>Tòa nhà</th>
            <th>Thao tác</th>
        </tr>
        <tr th:if="${#lists.isEmpty(apartments)}">
            <td colspan="7">Không có căn hộ nào</td>
        </tr>
        <tr th:each="apt : ${apartments}">
            <td th:text="${apt.id}"></td>
            <td th:text="${apt.apartmentNumber}"></td>
            <td th:text="${apt.area}"></td>
            <td th:text="${apt.price}"></td>
            <td th:text="${apt.status}"></td>
            <td th:text="${apt.building != null ? apt.building.name : 'N/A'}"></td>
            <td>
                <a th:href="@{/apartment/{id}(id=${apt.id})}">Xem</a>
                <a sec:authorize="hasRole('ADMIN')" th:href="@{/apartment/edit/{id}(id=${apt.id})}">Sửa</a>
                <a sec:authorize="hasRole('ADMIN')" th:href="@{/apartment/delete/{id}(id=${apt.id})}" 
                   onclick="return confirm('Xóa?')">Xóa</a>
            </td>
        </tr>
    </table>
    
    <a href="/">Về trang chủ</a>
</body>
</html>

auth
login.html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body>
    <h1>Đăng nhập</h1>
    
    <div th:if="${errorMessage}" th:text="${errorMessage}"></div>
    
    <form th:action="@{/login}" method="post">
        <div>
            <label>Username:</label>
            <input type="text" name="username" required>
        </div>
        <div>
            <label>Password:</label>
            <input type="password" name="password" required>
        </div>
        <button type="submit">Đăng nhập</button>
    </form>
    
    <div>
        <p>ADMIN: admin / 123456</p>
        <p>CUSTOMER: customer1 / 123456</p>
    </div>
    
    <a href="/">Về trang chủ</a>
</body>
</html>

index.html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/extras/spring-security">
<head>
    <meta charset="UTF-8">
    <title>Home</title>
</head>
<body>
    <h1>Spring Boot Apartment</h1>
    
    <div sec:authorize="isAuthenticated()">
        <p>Xin chào: <span sec:authentication="name"></span></p>
        <p>Role: 
            <span sec:authorize="hasRole('ADMIN')">ADMIN</span>
            <span sec:authorize="hasRole('CUSTOMER')">CUSTOMER</span>
        </p>
    </div>
    
    <div>
        <a sec:authorize="isAuthenticated()" href="/apartment">Quản lý Căn hộ</a>
        <a sec:authorize="!isAuthenticated()" href="/login">Đăng nhập</a>
        <a sec:authorize="isAuthenticated()" href="/logout">Đăng xuất</a>
    </div>
    
    <div>
        <h3>Tài khoản test:</h3>
        <p>ADMIN: admin / 123456</p>
        <p>CUSTOMER: customer1 / 123456</p>
    </div>
</body>
</html>

sql
-- ============================================
-- SQL SCRIPT - CRUD APARTMENT VỚI BIGDECIMAL
-- Database: apartment_db (MariaDB)
-- ============================================

CREATE DATABASE IF NOT EXISTS apartment_db;
USE apartment_db;

-- ============================================
-- TẠO BẢNG users (2 roles: ADMIN, CUSTOMER)
-- ============================================
DROP TABLE IF EXISTS apartments;
DROP TABLE IF EXISTS buildings;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'CUSTOMER' CHECK (role IN ('ADMIN', 'CUSTOMER'))
);

-- ============================================
-- TẠO BẢNG buildings (phải tạo trước)
-- ============================================
CREATE TABLE buildings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    address VARCHAR(500) NOT NULL
);

-- ============================================
-- TẠO BẢNG apartments (có quan hệ với buildings)
-- ============================================
CREATE TABLE apartments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    apartment_number VARCHAR(50) NOT NULL,
    area DOUBLE NOT NULL,
    price DECIMAL(19,2) NOT NULL,  -- Dùng DECIMAL cho BigDecimal
    status VARCHAR(20) NOT NULL,
    building_id BIGINT NOT NULL,
    FOREIGN KEY (building_id) REFERENCES buildings(id) ON DELETE CASCADE
);

-- ============================================
-- INSERT USERS
-- Password: 123456 (BCrypt: $2a$10$Ellwswcd53pvEzPxZzepd.jYQLjVilOUC7xpS0ZurnaWJ0D5KdA0y)
-- ============================================
INSERT INTO users (first_name, last_name, username, password, role) VALUES
('Admin', 'System', 'admin', '$2a$10$Ellwswcd53pvEzPxZzepd.jYQLjVilOUC7xpS0ZurnaWJ0D5KdA0y', 'ADMIN'),
('Nguyễn', 'Văn An', 'customer1', '$2a$10$Ellwswcd53pvEzPxZzepd.jYQLjVilOUC7xpS0ZurnaWJ0D5KdA0y', 'CUSTOMER'),
('Trần', 'Thị Bình', 'customer2', '$2a$10$Ellwswcd53pvEzPxZzepd.jYQLjVilOUC7xpS0ZurnaWJ0D5KdA0y', 'CUSTOMER');

-- ============================================
-- INSERT BUILDINGS
-- ============================================
INSERT INTO buildings (name, address) VALUES
('Tòa nhà A', '123 Đường ABC, Quận 1, TP.HCM'),
('Tòa nhà B', '456 Đường XYZ, Quận 2, TP.HCM'),
('Tòa nhà C', '789 Đường DEF, Quận 3, TP.HCM'),
('Tòa nhà D', '321 Đường GHI, Quận 4, TP.HCM'),
('Tòa nhà E', '654 Đường JKL, Quận 5, TP.HCM');

-- ============================================
-- INSERT APARTMENTS
-- ============================================
INSERT INTO apartments (apartment_number, area, price, status, building_id) VALUES
('A101', 50.5, 5000000.00, 'AVAILABLE', 1),
('A102', 60.0, 6000000.00, 'RENTED', 1),
('A201', 70.5, 7000000.00, 'AVAILABLE', 1),
('A301', 80.0, 8000000.00, 'AVAILABLE', 1),
('B101', 55.0, 5500000.00, 'AVAILABLE', 2),
('B102', 65.0, 6500000.00, 'SOLD', 2),
('B201', 75.0, 7500000.00, 'RENTED', 2),
('C101', 90.0, 9000000.00, 'AVAILABLE', 3),
('C201', 100.0, 10000000.00, 'AVAILABLE', 3),
('D101', 45.0, 4500000.00, 'RENTED', 4),
('E101', 85.0, 8500000.00, 'AVAILABLE', 5);

-- ============================================
-- THÔNG TIN ĐĂNG NHẬP
-- ============================================
-- ADMIN: admin / 123456
-- CUSTOMER: customer1 / 123456, customer2 / 123456

-- ============================================
-- QUERY TEST
-- ============================================
SELECT * FROM users;
SELECT * FROM buildings;
SELECT * FROM apartments;

-- Xem căn hộ kèm tên tòa nhà
SELECT a.id, a.apartment_number, a.area, a.price, a.status, b.name as building_name
FROM apartments a
JOIN buildings b ON a.building_id = b.id;

