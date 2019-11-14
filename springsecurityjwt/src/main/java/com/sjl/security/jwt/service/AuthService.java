package com.sjl.security.jwt.service;

import com.sjl.security.jwt.entity.JwtUser;

public interface AuthService {
	
	int register (JwtUser user);
	String login (String username, String password);

}
