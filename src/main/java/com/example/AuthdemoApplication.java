package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;


@EnableWebSecurity
@EnableOAuth2Client  // 启用 OAuth 2.0 客户端 
@SpringBootApplication
public class AuthdemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthdemoApplication.class, args);
	}
}
