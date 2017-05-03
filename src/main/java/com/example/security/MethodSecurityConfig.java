package com.example.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;

//@Configuration
//@WebAppConfiguration
//@EnableGlobalMethodSecurity(prePostEnabled = true)//, proxyTargetClass = true
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration
{

	@Autowired
	private OAuth2SecurityConfiguration securityConfig;

	@Override
	protected MethodSecurityExpressionHandler createExpressionHandler()
	{
		return new OAuth2MethodSecurityExpressionHandler();
	}
}
