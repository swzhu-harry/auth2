package com.example.config;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Resource;
import javax.servlet.Filter;

import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.filter.CompositeFilter;

@Configuration
//@EnableGlobalMethodSecurity(prePostEnabled = true) //	 启用方法安全设置
@EnableAuthorizationServer
//@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter
{

	/*private OAuth2ClientContext oauth2ClientContext;

	@Override
	protected void configure(HttpSecurity http) throws Exception
	{
		http.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class).antMatcher("/**").authorizeRequests()
				.antMatchers("/", "/index", "/403", "/css/**", "/js/**", "/fonts/**").permitAll()
				// 不设限制，都允许访问
				.anyRequest().authenticated().and().logout().logoutSuccessUrl("/").permitAll().and().csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
	}

	private Filter ssoFilter()
	{
		OAuth2ClientAuthenticationProcessingFilter githubFilter = new OAuth2ClientAuthenticationProcessingFilter("/login");
		OAuth2RestTemplate githubTemplate = new OAuth2RestTemplate(github(), oauth2ClientContext);
		githubFilter.setRestTemplate(githubTemplate);
		UserInfoTokenServices tokenServices = new UserInfoTokenServices(githubResource().getUserInfoUri(), github().getClientId());
		tokenServices.setRestTemplate(githubTemplate);
		githubFilter.setTokenServices(tokenServices);
		return githubFilter;

	}

	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter)
	{
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

	@Bean
	@ConfigurationProperties("github.resource")
	public ResourceServerProperties githubResource()
	{
		return new ResourceServerProperties();
	}

	@Bean
	@ConfigurationProperties("github.client")
	public AuthorizationCodeResourceDetails github()
	{
		return new AuthorizationCodeResourceDetails();
	}*/
	
		@Resource
	    private MyUserDetailsService userDetailService;

	    @Resource
	    private OAuth2ClientContext oauth2ClientContext;


	    @RequestMapping("/user")
	    public String user(Principal user) {

	        return "Hello" + user.getName();
	    }

	    @Override
	    @Bean // share AuthenticationManager for web and oauth
	    public AuthenticationManager authenticationManagerBean() throws Exception {
	        return super.authenticationManagerBean();
	    }

	    /**
	     * 主过滤器
	     *
	     * @param http
	     * @throws Exception
	     */
	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
	        http
//	                .headers()
//	                .frameOptions()
//	                .sameOrigin()
//	                .and()
	                //.csrf().disable()
	                // 跨域支持
	                .cors().and()
	                .antMatcher("/**")
	                .authorizeRequests()
	                .antMatchers("/", "/github", "/login**", "/webjars/**").permitAll()
	                .anyRequest().authenticated();
	        http
	                .exceptionHandling()
	                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
	                .and()
	                .formLogin().loginPage("/login").loginProcessingUrl("/login.do").defaultSuccessUrl("/success")
	                .failureUrl("/login?err=1")
	                .permitAll();
	        http
	                .logout()
	                .logoutUrl("/logout")               //默认只接受post请求处理,需要携带csrf token
	                .logoutSuccessUrl("/").permitAll()
	                .invalidateHttpSession(true)
	                .clearAuthentication(true)
	                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());    //csrf for angular
	        http
	                .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);

	    }


	    /**
	     * 授权服务器(定义UserDetails类)
	     *
	     */
	    @Override
	    protected void configure(AuthenticationManagerBuilder auth)
	            throws Exception {
	        // Configure spring security's authenticationManager with custom
	        // user details service
	        auth.userDetailsService(this.userDetailService);
	    }


	    /**
	     * 过滤器(第三方,需要注入到主过滤器)
	     *
	     */
	    private Filter ssoFilter() {
	        CompositeFilter filter = new CompositeFilter();
	        List<Filter> filters = new ArrayList<>();
	        filters.add(ssoFilter(github(), "/login/github"));
	        filter.setFilters(filters);
	        return filter;
	    }

	    @Bean
	    @ConfigurationProperties("github")
	    public ClientResources github() {
	        return new ClientResources();
	    }

	    /**
	     * 支持从本地重定向到第三方,由异常触发
	     *
	     */
	    @Bean
	    public FilterRegistrationBean oauth2ClientFilterRegistration(
	            OAuth2ClientContextFilter filter) {
	        FilterRegistrationBean registration = new FilterRegistrationBean();
	        registration.setFilter(filter);
	        registration.setOrder(-100);
	        return registration;
	    }

	    /**
	     * 本地的资源服务器
	     *
	     */
	    @Configuration
	    @EnableResourceServer
	    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
	        @Override
	        public void configure(HttpSecurity http) throws Exception {
	            http.antMatcher("/api/**").authorizeRequests().anyRequest().authenticated();
	        }
	    }

	    private Filter ssoFilter(ClientResources client, String path) {
	        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
	        OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
	        filter.setRestTemplate(template);
	        UserInfoTokenServices tokenServices = new UserInfoTokenServices(
	                client.getResource().getUserInfoUri(), client.getClient().getClientId());
	        tokenServices.setRestTemplate(template);
	        filter.setTokenServices(tokenServices);
	        return filter;
	    }

	    class ClientResources {

	        @NestedConfigurationProperty
	        private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

	        @NestedConfigurationProperty
	        private ResourceServerProperties resource = new ResourceServerProperties();

	        public AuthorizationCodeResourceDetails getClient() {
	            return client;
	        }

	        public ResourceServerProperties getResource() {
	            return resource;
	        }
	    }
}