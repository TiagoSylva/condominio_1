package br.com.mega.condominio.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private ImplementsUserDetailsService userDetailsService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
	    http.authorizeRequests()
	        .antMatchers("/").permitAll()//proprio spring já aciona "HOLE_", ficando HOLE_ADMIN
	        .anyRequest().authenticated()
	        .and().formLogin().loginPage("/entrar")
	            .defaultSuccessUrl("/").permitAll()
	        .and().logout()
	            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))//o spring sec. passará a aceitar /logout via get para efetuar logout
	                .permitAll().logoutSuccessUrl("/login");    
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {		
		auth.userDetailsService(userDetailsService)
		.passwordEncoder(new BCryptPasswordEncoder()); 
		
		
		 /*AUTENTICAÇÃO EM MEMÓRIA(ÚTIL PARA TESTES)
		 PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		   auth.inMemoryAuthentication()
		   .withUser("augusto").password(encoder.encode("123")).roles("ADMIN", "USER")
		   .and().withUser("otavio").password(encoder.encode("123")).roles("USER");*/
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/bootstrap/**");
	}

}

