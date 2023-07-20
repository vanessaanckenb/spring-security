package br.com.vanessaancken.springsecurity.service.authentication.converters;

import br.com.vanessaancken.springsecurity.domain.user.UserRole;
import br.com.vanessaancken.springsecurity.domain.user.resources.UserDTO;
import br.com.vanessaancken.springsecurity.domain.user.User;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class UserRequestToUserConverter {

    public User convert(UserDTO userDTO){
        return User
                .builder()
                .login(userDTO.login())
                .password(new BCryptPasswordEncoder().encode(userDTO.password()))
                .role(UserRole.USER)
                .build();
    }
}
