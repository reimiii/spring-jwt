package franxx.code.jwt.auth;

import franxx.code.jwt.config.JwtService;
import franxx.code.jwt.user.Role;
import franxx.code.jwt.user.User;
import franxx.code.jwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
  private final UserRepository repository;
  private final PasswordEncoder encoder;
  private final JwtService jwtService;

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

  public AuthResponse authenticate(AuthRequest request) {
    return null;
  }
}
