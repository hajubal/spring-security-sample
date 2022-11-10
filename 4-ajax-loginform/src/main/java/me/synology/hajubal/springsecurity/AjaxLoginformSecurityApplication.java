package me.synology.hajubal.springsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EnableJpaRepositories
@SpringBootApplication
public class AjaxLoginFormSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(AjaxLoginFormSecurityApplication.class, args);
	}
}
