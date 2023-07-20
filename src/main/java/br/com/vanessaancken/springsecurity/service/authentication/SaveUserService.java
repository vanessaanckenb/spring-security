package br.com.vanessaancken.springsecurity.service.authentication;

import br.com.vanessaancken.springsecurity.domain.user.resources.UserDTO;
import br.com.vanessaancken.springsecurity.repository.UserRepository;
import br.com.vanessaancken.springsecurity.service.authentication.converters.UserRequestToUserConverter;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@AllArgsConstructor
public class SaveUserService {

    private final UserRequestToUserConverter userRequestToUserConverter;
    private final UserRepository repository;

    @Transactional
    public void execute(UserDTO request){
        final var user = userRequestToUserConverter.convert(request);
        repository.save(user);
    }
}
