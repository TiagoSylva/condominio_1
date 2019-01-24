package br.com.mega.condominio;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class CondominioApplication {
	public static void main(String[] args) {
		SpringApplication.run(CondominioApplication.class, args);
		//System.out.print(new BCryptPasswordEncoder().encode("123"));
	}

}
