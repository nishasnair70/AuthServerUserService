package com.example.AuthorizationServer.endpoints;

import java.security.KeyPair;

import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;




@FrameworkEndpoint
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class JwkSetEndpoint {
	
	
	KeyPair keyPair;

	JwkSetEndpoint(KeyPair keyPair) {
		this.keyPair = keyPair;
	}

	@GetMapping("/.well-known/jwks.json")
	@ResponseBody
	public Map<String, Object> getKey() {
		RSAPublicKey publicKey = (RSAPublicKey) this.keyPair.getPublic();
		RSAKey key = new RSAKey.Builder(publicKey).build();
		return new JWKSet(key).toJSONObject();
	}

}
