package com.gslab.oidc.model;

import com.fasterxml.jackson.annotation.JsonView;
import com.gslab.oidc.jsonViews.Views;

public class User {
	@JsonView(Views.Public.class)
	String authorizationTokenEndpoint;
	
	@JsonView(Views.Public.class)
	String tokenEndpoint;
	
	@JsonView(Views.Public.class)
	String tokenKeysEndpoint;
	
	@JsonView(Views.Public.class)
	String clientId;

	//@JsonView(Views.Public.class)
	String clientSecret;

	@JsonView(Views.Public.class)
	String scope;

	@JsonView(Views.Public.class)
	String authorizationCodeFlow;

	public String getAuthorizationTokenEndpoint() {
		return authorizationTokenEndpoint;
	}

	public void setAuthorizationTokenEndpoint(String authorizationTokenEndpoint) {
		this.authorizationTokenEndpoint = authorizationTokenEndpoint;
	}

	public String getTokenEndpoint() {
		return tokenEndpoint;
	}

	public void setTokenEndpoint(String tokenEndpoint) {
		this.tokenEndpoint = tokenEndpoint;
	}

	public String getTokenKeysEndpoint() {
		return tokenKeysEndpoint;
	}

	public void setTokenKeysEndpoint(String tokenKeysEndpoint) {
		this.tokenKeysEndpoint = tokenKeysEndpoint;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope;
	}

	public String getAuthorizationCodeFlow() {
		return authorizationCodeFlow;
	}

	public void setAuthorizationCodeFlow(String authorizationCodeFlow) {
		this.authorizationCodeFlow = authorizationCodeFlow;
	}

	}