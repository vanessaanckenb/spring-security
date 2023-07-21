# spring-security tutorial

 <br/>

1-) Adicionar as dependencias do spring security:

```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-test</artifactId>
    <scope>test</scope>
</dependency>
```

<br/>

A principio o projeto tinha apenas o controller de Product e tudo que envolve seu CRUD, as requisições estavam publicas, funcionando normalmente sem qualquer tipo de segurança.
<br/>
Para deixar a api com autenticação e autorização o spring fornece bibliotecas prontas para isso.
<br/>
Adicionar as dependencias do Spring Security no pom.xml.
<br/>
Depois de adicionar essas dependencias, ao iniciar a aplicação, o spring faz uma configuração padrão:
<br/>
- cria um user e uma senha (é gerado um token e printado no console junto a inicialização do spring, como exemplo de token: 8efaa0b9-0507-4c6b-aad3-a5d5d344ca13, o username é user por padrão)
- bloqueia todas as requisições
<br/>
a senha muda sempre que executamos novamente o aplicativo, se quisermos mudar esse comportamento e tornar a senha estática, podemos adicionar a seguinte configuração ao nosso application.propertiesarquivo: spring.security.user.password=1234

<br/>

Agora, os enpoints que eram públicos, já não são mais, ao entrar no localhost:8080/products, que antes das dependencias funcionava, agora já não funciona mais, é retornado um 401 Unauthorized.

<br/>

Se for uma aplicação web, basta colocar o endereço no browser, ao tentar acessar o spring cria automaticamente uma tela de login e senha, basta colocar o usuario user e o password gerado.
Esse projeto é de uma aplicação rest, stateless, não de uma aplicação web que guarda sessão (stateful), então precisamos mudar a configuração padrão e mudarmos para stateless.

<br/><br/>


2-) Configurar que não queremos o processo de autenticação padrão do spring que abre a tela de login (statefull)
Para isso:
2.1-) Criar uma classe de configuração, dei o nome de SecurityConfigurations
2.2-) a classe deve ter a anotação @Configuration
2.3-) a classe deve ter a anotação @EnableWebSecurity
2.4-) deve ter um bean (@Bean) que faça essa configuração

```
@Configuration
@EnableWebSecurity
public class SecurityConfigurations {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
				.csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
}
```

- @EnableWebSecurity = indica ao spring que vamos personalizar as configurações de segurança
- @Bean = serve para exportar uma classe para o spring, fazendo com que ele consiga carrega-la e realize sua injecao de dependencia em outras classes. Para que o spring consiga instanciar a nossa classe.
- .csrf().disable() = desabilita a proteção contra ataque csrf cross-site request forgery, que é uma vulnerabilidade de segurança que afeta aplicativos da web atraves dos cookies, o csrf so ocorre quando é statefull. Vamos usar tokens, o token ja e uma protecao contra csrf.
- .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) = muda a configuração padrão de statefull para stateless

Pronto, agora as chamadas serão stateless e as requisições estão publicas novamente.
Se você digitar localhost:8080/products no browser, a tela de login não aparece mais e ja obtemos a resposta da api.
Queriamos que as requisições fossem stateless, ok, mas não queriamos que qualquer um pudesse acessar os endpoints sem autenticação e autorização, então vamos fazer essas configurações.

<br/><br/>

4-) Configurar que queremos ter autenticação nas chamadas
na mesma classe de configuração que criamos acima, no mesmo método, devemos adicionar:

```
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	return http
		.csrf(csrf -> csrf.disable())
		.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
		.authorizeHttpRequests(authorize -> authorize
				.requestMatchers(HttpMethod.POST, "/products").hasRole("ADMIN")
				.requestMatchers(HttpMethod.PUT, "/products").hasRole("ADMIN")
				.requestMatchers(HttpMethod.DELETE, "/products").hasRole("ADMIN")
				.requestMatchers(HttpMethod.POST, "/users/register").permitAll()
				.requestMatchers(HttpMethod.POST, "/users/login").permitAll()
				.anyRequest().authenticated()
		)
		.build();
}
```

- authorizeHttpRequests definimos quais endpoints queremos que tenha autorização ou não
- .requestMatchers(HttpMethod.POST, "/products").hasRole("ADMIN") aqui dizemos que somente o usuario que tiver a role ADMIN pode acessar esse endpoint com o método POST
após isso criaremos os users e roles e os endpoints do user e falaremos mais sobre isso
- como a parte de se registrar e fazer login deve ser publica, configuramos com o .permitAll()
- .anyRequest().authenticated() diz que qualquer outro endpoint precisa ser autenticado, mas que o usuario nao precisa ter uma role especifica, é um usuario qualquer que tenha se autenticado com seu login e senha, independente da sua role.

Pronto, agora bloqueamos todos nossos endpoints, menos o /users/register e o /users/login para o metodo post
nao criamos esses controlers ainda, mas ja sei que quero cria-los em breve
para os metodos post, put e delete em procuts, exigi que o user tenha a role de ADMIN

<br/>

Outra maneira de restringir o acesso a determinadas funcionalidades, com base no perfil dos usuários, é com a utilização de um recurso do Spring Security conhecido como Method Security, que funciona com a utilização de anotações em métodos:

```
@GetMapping("/{id}")
@Secured("ROLE_ADMIN")
public ResponseEntity detalhar(@PathVariable Long id) {
    var medico = repository.getReferenceById(id);
    return ResponseEntity.ok(new DadosDetalhamentoMedico(medico));
}
```

No exemplo de código anterior o método foi anotado com @Secured("ROLE_ADMIN"), para que apenas usuários com o perfil ADMIN possam disparar requisições para detalhar um médico. A anotação @Secured pode ser adicionada em métodos individuais ou mesmo na classe, que seria o equivalente a adicioná-la em todos os métodos.

Por padrão esse recurso vem desabilitado no spring Security, sendo que para o utilizar devemos adicionar a seguinte anotação na classe Securityconfigurations do projeto:
@EnableMethodSecurity(securedEnabled = true)

Para saber mais:
https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html

<br/>

Agora que esta tudo bloqueado, esperando uma autenticação e autorização, eu preciso criar tudo que envolve autenticação e autorização para liberar esses endpoints, como criação de users, criar um endpoint para fazer o cadastro e criar um endpoint para fazer o login

<br/><br/>

5-) Criar todo o contexto de usuarios para registro e login
Para que eu faça uma autenticação e autorização, eu preciso de todo um contexto de usuarios.
5.1) Criar uma tabela de usuarios que tenha login, senha e a role

```
create table users(
    id varchar(100) not null unique,
    login varchar(100) not null unique,
    password varchar(100) not null,
    role varchar(20) not null,
    primary key(id)
);
```

5.2-) criar uma entidade de usuario

```
@Table(name = "users")
@Entity(name = "User")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;
    private String login;
    private String password;
    private UserRole role;
}
```

5.3-) a entidade usuario deve implementar de UserDetails e sobreescrever seus metodos

```
@Table(name = "users")
@Entity(name = "User")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;
    private String login;
    private String password;
    private UserRole role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if(this.role == UserRole.ADMIN) {
            return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER"));
        }
       return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getUsername() {
        return this.login;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

A implementação correta de UserDetails garante que o Spring Security possa autenticar os usuários adequadamente, verificar suas autoridades e aplicar as regras de autorização definidas em seu aplicativo.
os metodos de sobreescrita obrigatorios ja configuram se o usuario esta ativo, se a credencial expira, se a conta é bloqueavel ou expiravel, você ja passa seu login e já configura as roles tambem.

A classe que implementa a interface UserDetailsService do Spring Security é responsável por carregar os detalhes do usuário a partir de uma fonte de dados, como um banco de dados.
Quando o usuário tenta fazer login, o Spring Security usará essa classe para autenticar o usuário e obter seus detalhes.


5.4-) criar o repository

```
@Repository
public interface UserRepository extends JpaRepository<User, String> {
}
```

5.5-) criar um controller para registrar os usuarios
lembrando que a senha deve ser salva em Bcrypt

```
@AllArgsConstructor
@RestController
@RequestMapping("/users")
public class UserController {

    private final SaveUserService saveUser;

    @PostMapping("/register")
    public ResponseEntity signIn(@RequestBody UserDTO user, UriComponentsBuilder uriComponentsBuilder){
        System.out.printf("[USER][REGISTER] " + user);
        saveUser.execute(user);
        return ResponseEntity.ok().build();
    }
}
```

5.6- agora que já adicionamos o user, o user deve enviar o email e senha
se forem corretos, receberão um token, que deve ser passado no header de cada requisição para se manter autorizado
no repository adicionar o metodo findByLogin que retorne um UserDetails
o spring vai fazer essa consulta para validação do usuario

```
@Repository
public interface UserRepository extends JpaRepository<User, String> {
    UserDetails findByLogin(String login);
}
```


5.7-) criar uma implementação do UserDetailsService, ou seja, uma classe que implemente o UserDetailsService
esse servico vai ser chamado automaticamente pelo spring toda vez que um usuario se autenticar
toda vez quem alguem tentar se autenticar na nossa aplicação, o spring security vai consultar esses usuarios
mas ele nao sabe que criamos uma tabela de user no banco de dados, ou buscamos o user de outra api, nao importa
aqui faremos a consulta dos nossos users pro spring security (nao importa se é no banco, chamando outra api...)
ate entao nos criamos toda a estrutura para salvarmos nosso user, mas ele nem precisaria estar salvo aqui, poderia ter sido de outro lugar
essa classe de fato vai buscar as infos do user, seja de onde for, e pegar os dados de necessarios para autenticação.

```
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByLogin(username);
    }
}
```

5.8-) Configurar a autenticação que chama o UserDetailsService por debaixo dos panos

```
@Configuration
@EnableWebSecurity
public class SecurityConfigurations {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(
                        authorize -> authorize
                            .requestMatchers(HttpMethod.POST, "/products").hasRole("ADMIN")
                            .requestMatchers(HttpMethod.PUT, "/products").hasRole("ADMIN")
                            .requestMatchers(HttpMethod.DELETE, "/products").hasRole("ADMIN")
                            .requestMatchers(HttpMethod.POST, "/users/register").permitAll()
                            .requestMatchers(HttpMethod.POST, "/users/login").permitAll()
                            .anyRequest().authenticated()
                )
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

- configurar o bean authenticationManager para injeção de dependencia do AuthenticationManager no controller
que chama o UserDetailsService por debaixo dos panos
Por isso antes criamos o UserDetailsServiceImpl que pega os dados do usuario guardados para conferir com os dados que o usuario passou
no caso guardamos no banco de dados
por isso antes criamos o metodo findByLogin no repositorio
ao adicionarmos o metodo authenticationManager, todos os endpoints precisariam de autenticacao
mesmo sem essa config no metodo acima

```
.authorizeHttpRequests(
	authorize -> authorize
		.requestMatchers(HttpMethod.POST, "/products").hasRole("ADMIN")
		.requestMatchers(HttpMethod.PUT, "/products").hasRole("ADMIN")
		.requestMatchers(HttpMethod.DELETE, "/products").hasRole("ADMIN")
		.requestMatchers(HttpMethod.POST, "/users/register").permitAll()
		.requestMatchers(HttpMethod.POST, "/users/login").permitAll()
		.anyRequest().authenticated()
	).build();
```

podemos ate adicionar essa autenticação por ultimo
para dizer qual realmente queremos autenticar, com qual role, qual queremos permitir...
- passwordEncoder
	configura que é usado o BCrypt
	ou seja
	no banco de dados salvamos a senha com o BCrypt, para nao deixar a senha exposta
	quando o user manda a senha aberta, ele converte em Bcrypt e faz o match com o que esta no banco
	se nao adicionarmos esse metodo, ao tentar fazer uma autenticação (ao chamar o endpoint do proximo passo) uma exceção será lançada.


5.9-) criar controller para user fazer a autenticação (para validar se nossos users estao autenticados)

```
@RestController
@RequestMapping("/login")
public class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody @Valid UserDTO request){
        var authenticationToken = new UsernamePasswordAuthenticationToken(request.login(), request.password());
        var authentication = authenticationManager.authenticate(authenticationToken);
        return ResponseEntity.ok().build();
    }
}
```

- AuthenticationManager = primeiro injetamos o AuthenticationManager
só conseguimos injetar ele porque no passo anterior condiguramos o seu bean
ao chamar o authenticationManager.authenticate(authenticationToken)
o UserDetailsServiceImpl é chamado, que chama o metodo findByLogin...
por isso fizemos tudo nessa ordem

resumo:
recebi dto contendo login e senha enviado pelo user
preciso consultar no banco de dados
disparar o processo de autenticacao
o processo de autenticacao esta na classe UserDetailsServiceImpl que implements UserDetailsService que chama o loadUserByUsername
esse metodo que usa o repository para fazer o select no banco de dados
mas nao é possivel chamar a classe AuthenticationService diretamente
AuthenticationManager, classe do spring que vamos chamar, chama a AuthenticationService por debaixo dos panos

criamos um endpoint de login, onde o user nos informa o login e senha, validamos
agora o proximo passo é: se a validação estiver ok, retornar para o user um token




6-) configurar token para retorno após validação
6.1) colocar a dependencia do auth jwt no pom

```
<dependency>
	<groupId>com.auth0</groupId>
	<artifactId>java-jwt</artifactId>
	<version>4.4.0</version>
</dependency>
```

6.2) criar classe TokenService com um metodo responsavel pela geração dos tokens e um metodo que valide o token

```
@Service
public class TokenService {

	@Value("${api.security.token.secret}")
	String secret;
	
    public String generateToken(User user){
        try {
            
            var algorithm = Algorithm.HMAC256(secret);
            return JWT
                    .create()
                    .withIssuer("auth-api")
                    .withSubject(user.getLogin())
                    .withExpiresAt(expirationDate())
                    .sign(algorithm);
        } catch (JWTCreationException exception){
            throw new RuntimeException("Erro ao gerar token" + exception);
        }
    }

    private Instant expirationDate() {
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
```

-Algorithm.HMAC256("SuaSenhaUnicaQueVaiGerarOHash") = senha secreta para fazer a assinatura do token
	não é boa pratica passar senha em texto dentro do codigo
	passar em uma variavel de ambiente pelo properties
	essa senha sera usada depois para validar os tokens, a geração do token pode estar em uma api de autenticaçõa e a validação podera estar em outras apis
-.withIssuer("auth-api") = identifica a api que é responsavel pelo token, quem esta emitindo o token, no caso eu coloquei auth-api porque seria minha api de autenticação
-withClain("chave", "valor") = se vc quiser passar mais infos dentro do token é dentro desse metodo, pode incluir outras informações no token JWT, de acordo com as necessidades da aplicação. 
	Por exemplo, podemos incluir o id do usuário no token, para isso basta utilizar o método withClaim .withClaim("id", usuario.getId())
-.withExpiresat() = para inserir um tempo de expiração do token, é importante que o token expire rapido por questões de segurança

no aplication properties:
api.security.token.secret=${JWT_SECRET:123456}

senhas e dados sensiveis sao lidas de variaveis de ambientes
para ler uma var de ambiente, usar ${}
:123456 = dizer para o spring, spring, procure essa var de ambiente JWT_SECRET, se nao encontrar use essa padrao que esta dps dos :


6.3) chamar o metodo da classe TokenService no controller

```
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
```

Agora, ao fazer login, você recebera um token de autenticação para usar nas proximas chamadas
precisamos de um método para validar esse token

6.4) criar método que valide o token

```
@Service
public class TokenService {

    @Value("${api.security.token.secret}")
    private String secret;

    public String gerarToken(Usuario usuario) {
        try {
            var algoritmo = Algorithm.HMAC256(secret);
            return JWT.create()
                    .withIssuer("API Voll.med")
                    .withSubject(usuario.getLogin())
                    .withExpiresAt(dataExpiracao())
                    .sign(algoritmo);
        } catch (JWTCreationException exception){
            throw new RuntimeException("erro ao gerar token jwt", exception);
        }
    }

    public String getSubject(String tokenJWT) {
        try {
            var algoritmo = Algorithm.HMAC256(secret);
            return JWT.require(algoritmo)
                    .withIssuer("API Voll.med")
                    .build()
                    .verify(tokenJWT)
                    .getSubject();
        } catch (JWTVerificationException exception) {
            throw new RuntimeException("Token JWT inválido ou expirado!");
        }
    }

    private Instant dataExpiracao() {
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }

}
```

Ao fazer uma chamada, a requisição passa pelos filtros e servlets e cai no controller. 
A requisição de login esta com permitAll(), entao não precisa de autenticação.
Depois que fizemos essa chamada, pegamos o token, devemos passar esse token no header das proximas requisições, mas onde isso é validado?
Por enquanto ainda não fizemos essa configuração.
Precisamos criar uma classe Filter, responsável por interceptar as requisições e realizar o processo de autenticação e autorização.

<br/><br/>

7-) Criar um filter para interceptar as requisições e validar os tokens antes da requisição de cair no controller

```
@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UsuarioRepository repository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var tokenJWT = recuperarToken(request);

        if (tokenJWT != null) {
            var subject = tokenService.getSubject(tokenJWT);
            var usuario = repository.findByLogin(subject);

            var authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }

    private String recuperarToken(HttpServletRequest request) {
        var authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null) {
            return authorizationHeader.replace("Bearer ", "");
        }

        return null;
    }
}
```

7.1) Adicionar o filtro antes de tudo
```
@Configuration
@EnableWebSecurity
public class SecurityConfigurations {

    @Autowired
    private SecurityFilter securityFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(req -> {
                    req.requestMatchers(HttpMethod.POST, "/login").permitAll();
                    req.anyRequest().authenticated();
                })
                .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
```

E para finalizar, tratei algumas exceções e status code no ExceptionsHanlder.
