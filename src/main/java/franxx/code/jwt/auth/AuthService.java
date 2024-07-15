package franxx.code.jwt.auth;

import franxx.code.jwt.config.JwtService;
import franxx.code.jwt.token.Token;
import franxx.code.jwt.token.TokenRepository;
import franxx.code.jwt.token.TokenType;
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
  private final TokenRepository tokenRepository;
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

    var savedUser = repository.save(user);
    var jwtToken = jwtService.generateToken(user);
    saveUserToken(savedUser, jwtToken);

    return AuthResponse.builder().token(jwtToken).build();
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

    revokeAllUserTokens(user);

    saveUserToken(user, token);

    return AuthResponse.builder().token(token).build();
  }

  private void saveUserToken(User user, String jwtToken) {
    var token = Token.builder()
        .user(user)
        .token(jwtToken)
        .tokenType(TokenType.BEARER)
        .expired(false)
        .revoked(false)
        .build();

    tokenRepository.save(token);
  }

  private void revokeAllUserTokens(User user) {
    var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());
    if (validUserTokens.isEmpty()) return;
    validUserTokens.forEach(token -> {
      token.setRevoked(true);
      token.setExpired(true);
    });

    tokenRepository.saveAll(validUserTokens);
  }
}
