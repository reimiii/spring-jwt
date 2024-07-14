package franxx.code.jwt.auth;

import franxx.code.jwt.config.JwtService;
import franxx.code.jwt.user.Role;
import franxx.code.jwt.user.User;
import franxx.code.jwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {
  private final UserRepository repository;
  private final PasswordEncoder encoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  @Transactional
  public AuthResponse register(RegisterRequest request) {
    var user = User.builder()
        .firstName(request.getFirstName())
        .lastName(request.getLastName())
        .email(request.getEmail())
        .password(encoder.encode(request.getPassword()))
        .role(Role.USER)
        .build();

    repository.save(user);
    String token = jwtService.generateToken(user);

    return AuthResponse.builder().token(token).build();
  }

  @Transactional
  public AuthResponse authenticate(AuthRequest request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
        )
    );

    User user = repository.findByEmail(request.getEmail())
        .orElseThrow(() -> new UsernameNotFoundException("username or password wrong"));

    String token = jwtService.generateToken(user);

    return AuthResponse.builder().token(token).build();
  }
}
