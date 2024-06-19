package com.example.resource_server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ResourceServerApplication {

	public static void main(String[] args) {
		System.out.println("리소스 서버 어플리케이션입니닷");
		SpringApplication.run(ResourceServerApplication.class, args);
	}

}
