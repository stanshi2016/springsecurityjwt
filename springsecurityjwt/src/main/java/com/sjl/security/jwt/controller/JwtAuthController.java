package com.sjl.security.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.sjl.security.jwt.entity.JwtUser;
import com.sjl.security.jwt.service.AuthService;

@RestController
public class JwtAuthController {
	
	@Autowired
	private AuthService authService;
	
	// 登录
    @RequestMapping(value = "/authentication/login", method = RequestMethod.POST)
    public String createToken( String username,String password ) throws AuthenticationException {
        return authService.login( username, password ); // 登录成功会返回JWT Token给用户
    }
	
    // 注册
    @RequestMapping(value = "/authentication/register", method = RequestMethod.POST)
    public int register( @RequestBody JwtUser user ) throws AuthenticationException {
        return authService.register(user);
    }

}
