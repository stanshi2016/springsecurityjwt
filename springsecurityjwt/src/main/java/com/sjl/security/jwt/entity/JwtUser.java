package com.sjl.security.jwt.entity;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Data;

@Data
public class JwtUser implements UserDetails{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private Long id;
	private String username;
	private String password;
	
    //权限
    private Collection<? extends GrantedAuthority> authorities;
    
    JwtUser(String username, String password, List<GrantedAuthority> authorities){
        this.username = username;
        this.password = password;
        this.authorities = authorities ;
    }

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
	}

	// 账号是否未过期
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	// 账户是否未锁定
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	// 密码是否未过期
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	// 账号是否激活
	@Override
	public boolean isEnabled() {
		return true;
	}
		

}
