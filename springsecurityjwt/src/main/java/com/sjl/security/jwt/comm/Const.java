package com.sjl.security.jwt.comm;

public class Const {
	
	public static final long EXPIRATION_TIME = 432_000_000; //5天
	public static final String SECRET = "CodeSheepSecret"; //JWT密码
	public static final String TOKEN_PREFIX = "Bearer"; //Token前缀
	public static final String HEADER_STRING = "Authorization"; //存放Token的Header key

}
