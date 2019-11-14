package com.sjl.security.jwt.mapper;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import com.sjl.security.jwt.entity.JwtUser;

public interface UserMapper { 
	
	@Select("select id, username, password form user where username = #{username}")
	JwtUser findByUsername(@Param("username") String username);
	
	@Insert("insert into user values(null,#{user.password}, #{user.username}")
    @Options(keyProperty="user.id",useGeneratedKeys=true)
	int save (@Param("user") JwtUser user); 

}
