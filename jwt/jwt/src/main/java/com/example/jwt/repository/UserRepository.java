package com.example.jwt.repository;
import com.example.jwt.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// repository : JPA레파지토리를 상속함
public interface UserRepository extends JpaRepository<User, Long> {
    @EntityGraph(attributePaths = "authorities")
    // username을 기준으로 User정보를 가져올 때 권한 정보도 같이 가져오게 된다.
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}