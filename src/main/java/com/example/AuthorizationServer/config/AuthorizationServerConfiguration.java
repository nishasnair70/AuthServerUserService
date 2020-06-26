package com.example.AuthorizationServer.config;

import java.security.KeyPair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.example.AuthorizationServer.endpoints.SubjectAttributeUserTokenConverter;

/**
 * The class will create and return json web token when the client
		  is properly authenticates.
 */

/**
 * 
 * Tell Spring to activate the authorization server.
 *
 */

@EnableAuthorizationServer
@Configuration
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter{

	@Autowired
	BCryptPasswordEncoder encoder;

	AuthenticationManager authenticationManager;
	KeyPair keyPair;
	boolean jwtEnabled;

	public AuthorizationServerConfiguration(
			AuthenticationConfiguration authenticationConfiguration,
			KeyPair keyPair,
			@Value("${security.oauth2.authorizationserver.jwt.enabled:true}") boolean jwtEnabled) throws Exception {

		this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
		this.keyPair = keyPair;
		this.jwtEnabled = jwtEnabled;
	}
	/**
	 * Function configure specifies what are the credentials that has to be given.
	 * 
	 * ||clients.inMemory() specifies that we are going to store the services in memory. 
	 * ||withClient ("client")is the user with whom we will identify.
	 * ||authorizedGrantTypes specify services that configure for the defined user.
	 * ||scopes ("read", "write") is the scope of the service. 
	 * ||secret(passwordEncoder (). encode ("password")) is the password of the client.
	 */
	@Override
	public void configure(ClientDetailsServiceConfigurer clients)
			throws Exception {
		
//		clients.inMemory()
//			.withClient("reader")
//				.authorizedGrantTypes("password")
//				.secret("{noop}secret")
//				.scopes("message:read")
//				.accessTokenValiditySeconds(600_000_000)
//				.and()
//			.withClient("writer")
//				.authorizedGrantTypes("password")
//				.secret("{noop}secret")
//				.scopes("message:write")
//				.accessTokenValiditySeconds(600_000_000)
//				.and()
//			.withClient("noscopes")
//				.authorizedGrantTypes("password")
//				.secret("{noop}secret")
//				.scopes("none")
//				.accessTokenValiditySeconds(600_000_000);
		
		clients.inMemory()
		.withClient("client").
		authorizedGrantTypes("password")
		.secret(encoder.encode("secret"))
		//.secret("{noop}secret")
		.scopes("message:read","message:write")
		.accessTokenValiditySeconds(600_000_000);
		
		
	}
	
	

	/**
	 * Function specifies which authentication controller and store of identifiers
	 * should use the end points.
	 */
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
		
		endpoints
			.authenticationManager(this.authenticationManager)
			.tokenStore(tokenStore());

		if (this.jwtEnabled) {
			endpoints
				.accessTokenConverter(accessTokenConverter());
		}
		
	}

	@Bean
	public TokenStore tokenStore() {
		if (this.jwtEnabled) {
			return new JwtTokenStore(accessTokenConverter());
		} else {
			return new InMemoryTokenStore();
		}
	}

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		converter.setKeyPair(this.keyPair);

		DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
		accessTokenConverter.setUserTokenConverter(new SubjectAttributeUserTokenConverter());
		converter.setAccessTokenConverter(accessTokenConverter);

		return converter;
	}
}
