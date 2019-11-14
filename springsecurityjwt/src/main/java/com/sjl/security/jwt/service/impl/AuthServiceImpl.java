package com.sjl.security.jwt.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.sjl.security.jwt.entity.JwtUser;
import com.sjl.security.jwt.mapper.UserMapper;
import com.sjl.security.jwt.service.AuthService;
import com.sjl.security.jwt.utils.JwtTokenUtil;

@Service
public class AuthServiceImpl implements AuthService {

	@Autowired
	private AuthenticationManager authenticationManager;
	
    @Autowired
    private UserDetailsService userDetailsService;
    
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    
    @Autowired
    private UserMapper userMapper;
	
	@Override
	public int register(JwtUser user) {
		final String username = user.getUsername();
        if( userMapper.findByUsername(username)!=null ) {
            return 0;
        }
        final String rawPassword = user.getPassword();
        
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        user.setPassword( encoder.encode(rawPassword) );
        return userMapper.save(user);
	}

	@Override
	public String login(String username, String password) {
		UsernamePasswordAuthenticationToken upToken = new UsernamePasswordAuthenticationToken(username, password);
		final Authentication authentication  = authenticationManager.authenticate(upToken);
        SecurityContextHolder.getContext().setAuthentication(authentication); //赋值给当前Sercurity Context
        final UserDetails userDetails = userDetailsService.loadUserByUsername( username);
        final String token = jwtTokenUtil.generateToken(userDetails);
		return token;
	}
	
	

}
