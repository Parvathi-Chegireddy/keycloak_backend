package com.spantag.oauth2_service;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class LoginContoller {
	
	 @GetMapping("/")
	    public String greet() {
	        return "Welcome";
	    }

}
