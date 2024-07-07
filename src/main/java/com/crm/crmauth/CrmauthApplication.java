package com.crm.crmauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;


@SpringBootApplication
public class CrmauthApplication {

	public static void main(String[] args) {
		SpringApplication.run(CrmauthApplication.class, args);
	}

}
