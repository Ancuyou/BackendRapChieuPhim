// MovieTickerBE_OLD/src/main/java/com/example/MovieTicker/config/security/CustomDecoder.java
package com.example.MovieTicker.config.security;

import com.example.MovieTicker.repository.InvalidatedRepository;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Date;
import java.util.Objects;

@Component
public class CustomDecoder implements JwtDecoder {

    @Value("${jwt.Key}")
    private String signerKey;

    // Tiêm trực tiếp InvalidatedRepository vào đây
    @Autowired
    private InvalidatedRepository invalidatedRepository;

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // 1. Xác thực chữ ký của token
            MACVerifier verifier = new MACVerifier(signerKey.getBytes());
            if (!signedJWT.verify(verifier)) {
                throw new JwtException("Invalid token signature");
            }

            // 2. Kiểm tra xem token đã hết hạn chưa
            Date expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();
            if (expiryTime.before(new Date())) {
                throw new JwtException("Token has expired");
            }

            // 3. KIỂM TRA QUAN TRỌNG NHẤT: Token có trong danh sách vô hiệu hóa (đã logout) không?
            String jit = signedJWT.getJWTClaimsSet().getJWTID();
            if (invalidatedRepository.existsById(jit)) {
                throw new JwtException("Token has been invalidated (logged out)");
            }

            // Nếu tất cả kiểm tra đều thành công, tạo đối tượng Jwt trả về cho Spring
            return new Jwt(
                    token,
                    Objects.requireNonNull(signedJWT.getJWTClaimsSet().getIssueTime()).toInstant(),
                    Objects.requireNonNull(expiryTime).toInstant(),
                    signedJWT.getHeader().toJSONObject(),
                    signedJWT.getJWTClaimsSet().getClaims()
            );

        } catch (ParseException | JOSEException e) {
            // Lỗi này xảy ra khi token không đúng định dạng JWT
            throw new JwtException("Invalid token format");
        }
    }
}