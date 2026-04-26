package com.guicedee.microprofile.jwt.test;

import com.guicedee.microprofile.jwt.MicroProfileJwtContext;
import com.guicedee.microprofile.jwt.VertxJsonWebToken;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the MicroProfile JWT bridge — verifies that:
 * <ul>
 *   <li>{@link VertxJsonWebToken} correctly maps Vert.x User claims to MP JWT</li>
 *   <li>{@link MicroProfileJwtContext} ThreadLocal context works correctly</li>
 * </ul>
 */
class MicroProfileJwtTest
{
    @AfterEach
    void clearContext()
    {
        MicroProfileJwtContext.clear();
    }

    // -- VertxJsonWebToken unit tests --

    @Test
    void testVertxJsonWebTokenGetName_upn()
    {
        User user = createUser(new JsonObject()
                .put("upn", "alice@example.com")
                .put("sub", "alice-id"));
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        assertEquals("alice@example.com", jwt.getName());
    }

    @Test
    void testVertxJsonWebTokenGetName_fallsBackToSub()
    {
        User user = createUser(new JsonObject()
                .put("sub", "alice-id"));
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        assertEquals("alice-id", jwt.getName());
    }

    @Test
    void testVertxJsonWebTokenStandardClaims()
    {
        User user = createUser(new JsonObject()
                .put("sub", "user-123")
                .put("iss", "https://auth.example.com")
                .put("jti", "token-abc")
                .put("exp", 1700000000L)
                .put("iat", 1699990000L)
                .put("groups", new JsonArray().add("admin").add("user")));
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        assertEquals("user-123", jwt.getSubject());
        assertEquals("https://auth.example.com", jwt.getIssuer());
        assertEquals("token-abc", jwt.getTokenID());
        assertEquals(1700000000L, jwt.getExpirationTime());
        assertEquals(1699990000L, jwt.getIssuedAtTime());
        assertEquals(Set.of("admin", "user"), jwt.getGroups());
    }

    @Test
    void testVertxJsonWebTokenAudience()
    {
        User user = createUser(new JsonObject()
                .put("aud", new JsonArray().add("api1").add("api2")));
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        assertEquals(Set.of("api1", "api2"), jwt.getAudience());
    }

    @Test
    void testVertxJsonWebTokenClaimNames()
    {
        User user = createUser(new JsonObject()
                .put("sub", "x")
                .put("custom", "value"));
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        assertTrue(jwt.getClaimNames().contains("sub"));
        assertTrue(jwt.getClaimNames().contains("custom"));
    }

    @Test
    void testVertxJsonWebTokenGetClaim()
    {
        User user = createUser(new JsonObject()
                .put("custom_claim", "hello"));
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        assertEquals("hello", jwt.<String>getClaim("custom_claim"));
        assertNull(jwt.getClaim("nonexistent"));
    }

    @Test
    void testVertxJsonWebTokenContainsClaim()
    {
        User user = createUser(new JsonObject()
                .put("sub", "test"));
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        assertTrue(jwt.containsClaim("sub"));
        assertFalse(jwt.containsClaim("nonexistent"));
    }

    @Test
    void testVertxJsonWebTokenAudienceSingleString()
    {
        User user = createUser(new JsonObject()
                .put("aud", "single-audience"));
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        assertEquals(Set.of("single-audience"), jwt.getAudience());
    }

    @Test
    void testVertxJsonWebTokenGroupsSingleString()
    {
        User user = createUser(new JsonObject()
                .put("groups", "admin"));
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        assertEquals(Set.of("admin"), jwt.getGroups());
    }

    @Test
    void testVertxJsonWebTokenEmptyPrincipal()
    {
        User user = createUser(new JsonObject());
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        assertNull(jwt.getSubject());
        assertNull(jwt.getIssuer());
        assertNull(jwt.getTokenID());
        assertEquals(0L, jwt.getExpirationTime());
        assertEquals(0L, jwt.getIssuedAtTime());
        assertEquals(Set.of(), jwt.getGroups());
        assertEquals(Set.of(), jwt.getAudience());
    }

    // -- Context tests --

    @Test
    void testContextSetAndGet()
    {
        User user = createUser(new JsonObject().put("sub", "ctx-user"));
        MicroProfileJwtContext.setCurrent(new VertxJsonWebToken(user));

        JsonWebToken jwt = MicroProfileJwtContext.getCurrent();
        assertNotNull(jwt);
        assertEquals("ctx-user", jwt.getSubject());
    }

    @Test
    void testContextClear()
    {
        User user = createUser(new JsonObject().put("sub", "temp"));
        MicroProfileJwtContext.setCurrent(new VertxJsonWebToken(user));
        assertNotNull(MicroProfileJwtContext.getCurrent());

        MicroProfileJwtContext.clear();
        assertNull(MicroProfileJwtContext.getCurrent());
    }

    @Test
    void testContextSetNull()
    {
        User user = createUser(new JsonObject().put("sub", "temp"));
        MicroProfileJwtContext.setCurrent(new VertxJsonWebToken(user));
        MicroProfileJwtContext.setCurrent(null);
        assertNull(MicroProfileJwtContext.getCurrent());
    }

    @Test
    void testVertxUserAccessor()
    {
        User user = createUser(new JsonObject().put("sub", "test"));
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);
        assertSame(user, jwt.getVertxUser());
    }

    // -- Helper --

    private static User createUser(JsonObject principal)
    {
        return User.create(principal);
    }
}
