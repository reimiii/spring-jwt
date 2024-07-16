package franxx.code.jwt;

import franxx.code.jwt.auth.AuthService;
import franxx.code.jwt.auth.RegisterWithRoleRequest;
import franxx.code.jwt.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringJwtApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(
			AuthService authService
	) {
		 return args -> {
			 var admin = RegisterWithRoleRequest.builder()
					 .firstName("Admin")
					 .lastName("Admin")
					 .email("admin@admin.com")
					 .password("password")
					 .role(Role.ADMIN)
					 .build();


			 var manager = RegisterWithRoleRequest.builder()
					 .firstName("Manager")
					 .lastName("Manager")
					 .email("manager@manager.com")
					 .password("password")
					 .role(Role.MANAGER)
					 .build();

			 System.out.println("admin token: " + authService.registerWithRole(admin).getAccessToken());
			 System.out.println("manager token: " + authService.registerWithRole(manager).getAccessToken());
		 };
	}

}
