package com.example.AuthorizationServer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
//import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import com.example.AuthorizationServer.Filter.CustomFilter;
//import com.example.AuthorizationServer.Filter.JwtRequestFilter;
//import com.example.AuthorizationServer.Filter.JwtRequestFilter;
import com.example.AuthorizationServer.Service.UserDetailsServiceImpl;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
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
public class UserConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserDetailsService userDetailsService;

	

	@Bean
	protected AuthenticationManager getAuthenticationManager() throws Exception {
		return super.authenticationManagerBean();
	}

//	    @Bean
//	    PasswordEncoder passwordEncoder() {
//	        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//	    }

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		http.cors().and()
//		//.addFilterBefore(new TokenFilter(), ChannelProcessingFilter.class)
//		.addFilterBefore(new CustomFilter(), SessionManagementFilter.class)
//		.authorizeRequests()
//		        .antMatchers(HttpMethod.OPTIONS).permitAll()
//	            .antMatchers("/oauth/token").permitAll() 
//		        //.mvcMatchers("/save").permitAll()
//				.mvcMatchers("/.well-known/jwks.json").permitAll()
//				.anyRequest().authenticated()
//				.and().httpBasic()
//				.and()
//			.csrf().ignoringRequestMatchers(request -> "/introspect".equals(request.getRequestURI()))
//			;

		//http.cors().and()
				// .addFilterBefore(jwtRequestFilter,
				// UsernamePasswordAuthenticationFilter.class)
				// .addFilterBefore(new CustomFilter(), ChannelProcessingFilter.class)
				//.authorizeRequests().antMatchers(HttpMethod.OPTIONS).permitAll().antMatchers(HttpMethod.POST)
				//.permitAll().antMatchers("/oauth/token").permitAll().mvcMatchers("/.well-known/jwks.json").permitAll()
				//.anyRequest().authenticated().and().httpBasic().and().csrf().disable();
//	            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		// .ignoringRequestMatchers(request ->
		// "/introspect".equals(request.getRequestURI()));


		 http
		 .cors().and() .authorizeRequests()
		 .antMatchers("/oauth/token").permitAll() 
		 .antMatchers(HttpMethod.POST).permitAll()
		.mvcMatchers("/save").permitAll()
			.mvcMatchers("/.well-known/jwks.json").permitAll()
			 .anyRequest().authenticated()
	            .and().httpBasic()
	            .and().csrf()
	            .disable();

	}

	@Bean
    public FilterRegistrationBean corsFilterRegistrationBean() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.applyPermitDefaultValues();
        config.setAllowCredentials(true);
        config.setAllowedOrigins(Arrays.asList("*"));
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setAllowedMethods(Arrays.asList("*"));
        config.setExposedHeaders(Arrays.asList("content-length"));
        config.setMaxAge(3600L);
        source.registerCorsConfiguration("/**", config);
        FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
        bean.setOrder(0);
        return bean;
    }

	@Override
	public void configure(WebSecurity web) throws Exception {
	    web.ignoring().antMatchers(HttpMethod.OPTIONS, "/oauth/token");
	}




}
