package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


//@EnableWebSecurity
//@EnableOAuth2Client  // 启用 OAuth 2.0 客户端 
@SpringBootApplication
public class AuthdemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthdemoApplication.class, args);
	}
}
