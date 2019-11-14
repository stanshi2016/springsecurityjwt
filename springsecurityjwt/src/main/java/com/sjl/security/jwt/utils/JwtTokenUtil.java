package com.sjl.security.jwt.utils;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sjl.security.jwt.comm.Const;
import com.sjl.security.jwt.entity.JwtUser;

public class JwtTokenUtil {
	
	/*token 密钥*/
	public static final String SECRET = "JKKLJOoasdlfj";
	
	/*token 过期时间: 10天 */
	public static final int calendarField = Calendar.DATE;
	
	public static final int calendarInterval = 10; 
	
	public String generateToken(UserDetails userDetails) {
		
		Date iatDate = new Date();
		Date expDate = new Date(System.currentTimeMillis() + Const.EXPIRATION_TIME * 1000);

		Map<String, Object> headMap = new HashMap<>();
		headMap.put("alg", "HS256");
		headMap.put("typ", "JWT");
		
		String token = JWT.create().withHeader(headMap) //header
				.withClaim("iss", "kuka") // payload
                .withClaim("aud", "APP").
                withClaim("user_id", null == userDetails.getUsername() ? null : userDetails.getUsername())
                .withIssuedAt(iatDate) // sign time
                .withExpiresAt(expDate) // expire time
                .sign(Algorithm.HMAC256(Const.SECRET)); // signature		
		return token;
				
	}
	public String getUsernameFromToken(String token){
		Map<String, Claim> claims = verifyToken(token);
		Claim user_name_claim = claims.get("user_id");
		return user_name_claim.asString();
	}
	
	public Boolean validateToken(String token, UserDetails userDetails) {
        JwtUser user = (JwtUser) userDetails;
        final String username = getUsernameFromToken(token);
        return (
                username.equals(user.getUsername())
                        && !isTokenExpired(token)
                        );
    }
	
	private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
	}
	
	public Date getExpirationDateFromToken(String token) {
		Map<String, Claim> claims = verifyToken(token);
		Claim exp_claim = claims.get(PublicClaims.EXPIRES_AT);
        return exp_claim.asDate();
    }
	
	public static String createToken (Long user_id) throws Exception{
		
		Date iatDate = new Date();
		//expire time  
		Calendar nowTime = Calendar.getInstance();
		nowTime.add(calendarField, calendarInterval);
		Date expiresDate = nowTime.getTime();
		
		//header Map
		Map<String, Object> map = new HashMap<>();
		map.put("alg", "HS256");
		map.put("typ", "JWT");
		
		String token = JWT.create().withHeader(map) //header
				.withClaim("iss", "Service") // payload
                .withClaim("aud", "APP").withClaim("user_id", null == user_id ? null : user_id.toString())
                .withIssuedAt(iatDate) // sign time
                .withExpiresAt(expiresDate) // expire time
                .sign(Algorithm.HMAC256(SECRET)); // signature		
		return token;
	}
	
	
	 /**
     * 解密Token
     * 
     * @param token
     * @return
     * @throws Exception
     */
    public static Map<String, Claim> verifyToken(String token) {
        DecodedJWT jwt = null;
        try {
            JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET)).build();
            jwt = verifier.verify(token);
        } catch (Exception e) {
            // e.printStackTrace();
            // token 校验失败, 抛出Token验证非法异常
        }
        return jwt.getClaims();
    }
    
	 /**
	     * 根据Token获取user_id
	     * 
	     * @param token
	     * @return user_id
	     */
	    public static Long getAppUID(String token) {
	        Map<String, Claim> claims = verifyToken(token);
	        Claim user_id_claim = claims.get("user_id");
	        if (null == user_id_claim || StringUtils.isEmpty(user_id_claim.asString())) {
	            // token 校验失败, 抛出Token验证非法异常
	        }
	        return Long.valueOf(user_id_claim.asString());
	    }


}
