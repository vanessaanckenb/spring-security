package br.com.vanessaancken.springsecurity.controller;

import br.com.vanessaancken.springsecurity.domain.user.User;
import br.com.vanessaancken.springsecurity.domain.user.resources.JwtDTO;
import br.com.vanessaancken.springsecurity.domain.user.resources.UserDTO;
import br.com.vanessaancken.springsecurity.service.authentication.SaveUserService;
import br.com.vanessaancken.springsecurity.service.authentication.TokenService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

@AllArgsConstructor
@RestController
@RequestMapping("/users")
public class AuthenticationController {

    private final SaveUserService saveUser;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    @PostMapping("/register")
    public ResponseEntity signIn(@RequestBody UserDTO user, UriComponentsBuilder uriComponentsBuilder){
        System.out.printf("[USER][REGISTER] " + user);
        saveUser.execute(user);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody @Valid UserDTO request){
        var authenticationToken = new UsernamePasswordAuthenticationToken(request.login(), request.password());
        var authentication = authenticationManager.authenticate(authenticationToken);
        var jtwToken = tokenService.generateToken((User) authentication.getPrincipal());
        return ResponseEntity.ok(new JwtDTO(jtwToken));
    }
}
