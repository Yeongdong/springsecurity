package io.springsecurity.springsecuritymaster;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class SpringsecuritymasterApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringsecuritymasterApplication.class, args);
	}

}
