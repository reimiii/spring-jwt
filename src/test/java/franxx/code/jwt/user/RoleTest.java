package franxx.code.jwt.user;

import org.junit.jupiter.api.Test;

class RoleTest {

  @Test
  void name() {
    Role admin = Role.ADMIN;

    System.out.println(admin.getAuthorities());
  }
}