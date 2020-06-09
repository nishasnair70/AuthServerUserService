package com.example.AuthorizationServer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import com.example.AuthorizationServer.Service.UserDetailsServiceImpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.*;
import org.springframework.security.config.annotation.authentication.builders.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class UserConfig extends WebSecurityConfigurerAdapter{
	
	 @Autowired
	    private UserDetailsService userDetailsService;

	    @Bean
	    protected AuthenticationManager getAuthenticationManager() throws Exception {
	        return super.authenticationManagerBean();
	    }

	    @Bean
	    PasswordEncoder passwordEncoder() {
	        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	    }


	    @Override
	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	    }
    
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.mvcMatchers("/.well-known/jwks.json").permitAll()
				.anyRequest().authenticated()
				.and().httpBasic()
				.and()
			.csrf().ignoringRequestMatchers(request -> "/introspect".equals(request.getRequestURI()))
			;
	}

	

}
