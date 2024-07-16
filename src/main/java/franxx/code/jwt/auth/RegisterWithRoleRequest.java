package franxx.code.jwt.auth;

import franxx.code.jwt.user.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RegisterWithRoleRequest {
  private String firstName;
  private String lastName;
  private String email;
  private String password;
  private Role role;
}
