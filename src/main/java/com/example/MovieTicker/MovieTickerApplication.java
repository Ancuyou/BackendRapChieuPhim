package com.example.MovieTicker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableFeignClients(basePackages = "com.example.MovieTicker.config")
@EnableScheduling
public class MovieTickerApplication {

	public static void main(String[] args) {
		SpringApplication.run(MovieTickerApplication.class, args);
	}

}
