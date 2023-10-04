
package dev.uncomplex.jwt;

import dev.uncomplex.json.JsonString;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 *
 * @author James Thorpe <james@uncomplex.dev>
 */
public class JwtBuilderTest {
    
    static final Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    static final Instant expiresAt = now.plus(5, ChronoUnit.MINUTES);
    static final Instant issuedAt = now.minus(5, ChronoUnit.MINUTES);

    /**
     * Test of claim method, of class JwtBuilder.
     */
    @Test
    public void test() {
        Jwt jwt = buildJwt();
        validateJwt(jwt);
    }

    static void validateJwt(Jwt jwt) {
        assertEquals(jwt.algorithm(), Jwt.Algorithm.HS256);
        assertEquals(jwt.audience(), "audience");
        assertEquals(jwt.claim("claim"), new JsonString("claim"));
        assertEquals(jwt.contentType(), "content-type");
        assertEquals(jwt.expiresAt(), expiresAt);
        assertFalse(jwt.isExpired());
        assertEquals(jwt.header("header"), new JsonString("header"));
        assertEquals(jwt.id(), "id");
        assertEquals(jwt.issuedAt(), issuedAt);
        assertEquals(jwt.issuer(), "uncomplex.dev");
        assertEquals(jwt.kid(), "key-id");
        assertEquals(jwt.notBefore(), now);
        assertEquals(jwt.subject(), "test");
    }

    static Jwt buildJwt() {
        var jwt = new JwtBuilder()
                .algorithm(Jwt.Algorithm.HS256)
                .audience("audience")
                .claim("claim", "claim")
                .contentType("content-type")
                .expiresAt(expiresAt)
                .header("header", "header")
                .id("id")
                .issuedAt(issuedAt)
                .issuer("uncomplex.dev")
                .kid("key-id")
                .notBefore(now)
                .subject("test")
                .type("JWT")
                .build();
        return jwt;
    }

    @Test
    public void testExpiry() {
        var j = new JwtBuilder()
                .expiresAt(issuedAt)
                .build();
        assertEquals(j.expiresAt(), issuedAt);
        assertTrue(j.isExpired());
    }
}
