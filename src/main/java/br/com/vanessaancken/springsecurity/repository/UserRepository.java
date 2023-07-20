package br.com.vanessaancken.springsecurity.repository;

import br.com.vanessaancken.springsecurity.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, String> {
    User findByLogin(String login);
}
