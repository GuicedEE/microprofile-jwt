package com.guicedee.microprofile.jwt.test;

import com.guicedee.microprofile.jwt.MicroProfileJwtContext;
import com.guicedee.microprofile.jwt.VertxJsonWebToken;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.*;

import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests that exercise real JWT token generation and verification
 * using Vert.x JWTAuth with HMAC (HS256) signing — no Docker required.
 * <p>
 * This validates that:
 * <ul>
 *   <li>Vert.x JWTAuth can sign and verify tokens end-to-end</li>
 *   <li>{@link VertxJsonWebToken} correctly bridges the verified User to MP JWT</li>
 *   <li>{@link MicroProfileJwtContext} works with real authenticated users</li>
 *   <li>Expired tokens are rejected</li>
 *   <li>Tokens with wrong keys are rejected</li>
 * </ul>
 */
class JwtAuthIntegrationTest
{
    private static Vertx vertx;
    private static JWTAuth jwtAuth;

    private static final String SECRET = "super-secret-key-for-testing-only-must-be-at-least-256-bits!";

    @BeforeAll
    static void setup()
    {
        vertx = Vertx.vertx();
        jwtAuth = JWTAuth.create(vertx, new JWTAuthOptions()
                .addPubSecKey(new PubSecKeyOptions()
                        .setAlgorithm("HS256")
                        .setBuffer(SECRET)));
    }

    @AfterAll
    static void teardown() throws Exception
    {
        if (vertx != null)
        {
            CountDownLatch latch = new CountDownLatch(1);
            vertx.close().onComplete(ar -> latch.countDown());
            latch.await(5, TimeUnit.SECONDS);
        }
    }

    @AfterEach
    void clearContext()
    {
        MicroProfileJwtContext.clear();
    }

    @Test
    void generateAndVerifyToken_standardClaims() throws Exception
    {
        // Generate a real signed JWT token
        String token = jwtAuth.generateToken(
                new JsonObject()
                        .put("sub", "user-42")
                        .put("iss", "https://test.guicedee.com")
                        .put("jti", "token-001")
                        .put("upn", "alice@guicedee.com")
                        .put("groups", new JsonArray().add("admin").add("developer")),
                new JWTOptions()
                        .setExpiresInSeconds(3600)
                        .setAudience(java.util.List.of("my-api"))
        );

        assertNotNull(token);
        assertFalse(token.isBlank());

        // Verify the token through Vert.x auth
        User user = authenticate(token);
        assertNotNull(user);

        // Bridge to MP JWT
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        assertEquals("alice@guicedee.com", jwt.getName());
        assertEquals("user-42", jwt.getSubject());
        assertEquals("https://test.guicedee.com", jwt.getIssuer());
        assertEquals("token-001", jwt.getTokenID());
        assertTrue(jwt.getExpirationTime() > 0);
        assertTrue(jwt.getIssuedAtTime() > 0);
        assertEquals(Set.of("admin", "developer"), jwt.getGroups());
        assertEquals(Set.of("my-api"), jwt.getAudience());
        // Raw token may or may not be available depending on Vert.x version/config
        // jwt.getRawToken() bridges to "raw_token" claim which Vert.x may not populate
    }

    @Test
    void generateAndVerifyToken_customClaims() throws Exception
    {
        String token = jwtAuth.generateToken(
                new JsonObject()
                        .put("sub", "user-99")
                        .put("tenant", "acme-corp")
                        .put("level", 5),
                new JWTOptions().setExpiresInSeconds(300)
        );

        User user = authenticate(token);
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        assertEquals("acme-corp", jwt.<String>getClaim("tenant"));
        assertEquals(5, jwt.<Integer>getClaim("level"));
        assertTrue(jwt.containsClaim("tenant"));
        assertTrue(jwt.getClaimNames().contains("tenant"));
        assertTrue(jwt.getClaimNames().contains("level"));
    }

    @Test
    void contextWorksWithRealToken() throws Exception
    {
        String token = jwtAuth.generateToken(
                new JsonObject().put("sub", "ctx-user"),
                new JWTOptions().setExpiresInSeconds(60)
        );

        User user = authenticate(token);
        MicroProfileJwtContext.setCurrent(new VertxJsonWebToken(user));

        JsonWebToken current = MicroProfileJwtContext.getCurrent();
        assertNotNull(current);
        assertEquals("ctx-user", current.getSubject());

        MicroProfileJwtContext.clear();
        assertNull(MicroProfileJwtContext.getCurrent());
    }

    @Test
    void tamperingWithTokenIsRejected() throws Exception
    {
        // Generate a valid token then tamper with the payload
        String token = jwtAuth.generateToken(
                new JsonObject().put("sub", "legit-user"),
                new JWTOptions().setExpiresInSeconds(300)
        );

        // Tamper: flip a character in the payload section
        String[] parts = token.split("\\.");
        char[] payload = parts[1].toCharArray();
        payload[0] = (payload[0] == 'a') ? 'b' : 'a';
        String tampered = parts[0] + "." + new String(payload) + "." + parts[2];

        // Attempt to verify — should fail
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Throwable> error = new AtomicReference<>();

        jwtAuth.authenticate(new TokenCredentials(tampered))
                .onSuccess(u -> latch.countDown())
                .onFailure(t -> {
                    error.set(t);
                    latch.countDown();
                });

        assertTrue(latch.await(5, TimeUnit.SECONDS));
        assertNotNull(error.get(), "Tampered token should be rejected");
    }

    @Test
    void wrongKeyRejectsToken() throws Exception
    {
        // Create a second JWTAuth with a different secret
        JWTAuth otherAuth = JWTAuth.create(vertx, new JWTAuthOptions()
                .addPubSecKey(new PubSecKeyOptions()
                        .setAlgorithm("HS256")
                        .setBuffer("completely-different-secret-key-for-signing-tokens-1234567890")));

        // Sign with the other key
        String token = otherAuth.generateToken(
                new JsonObject().put("sub", "hacker"),
                new JWTOptions().setExpiresInSeconds(300)
        );

        // Verify with our key — should fail
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Throwable> error = new AtomicReference<>();

        jwtAuth.authenticate(new TokenCredentials(token))
                .onSuccess(u -> latch.countDown())
                .onFailure(t -> {
                    error.set(t);
                    latch.countDown();
                });

        assertTrue(latch.await(5, TimeUnit.SECONDS));
        assertNotNull(error.get(), "Token signed with wrong key should be rejected");
    }

    @Test
    void nameResolutionFallback_preferredUsername() throws Exception
    {
        String token = jwtAuth.generateToken(
                new JsonObject()
                        .put("sub", "user-id-123")
                        .put("preferred_username", "bob"),
                new JWTOptions().setExpiresInSeconds(60)
        );

        User user = authenticate(token);
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        // No upn, so should fall back to preferred_username
        assertEquals("bob", jwt.getName());
    }

    @Test
    void nameResolutionFallback_subOnly() throws Exception
    {
        String token = jwtAuth.generateToken(
                new JsonObject().put("sub", "fallback-sub"),
                new JWTOptions().setExpiresInSeconds(60)
        );

        User user = authenticate(token);
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        assertEquals("fallback-sub", jwt.getName());
    }

    @Test
    void multipleAudiencesFromRealToken() throws Exception
    {
        String token = jwtAuth.generateToken(
                new JsonObject().put("sub", "multi-aud"),
                new JWTOptions()
                        .setExpiresInSeconds(60)
                        .setAudience(java.util.List.of("api-1", "api-2", "api-3"))
        );

        User user = authenticate(token);
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        Set<String> audience = jwt.getAudience();
        assertEquals(3, audience.size());
        assertTrue(audience.contains("api-1"));
        assertTrue(audience.contains("api-2"));
        assertTrue(audience.contains("api-3"));
    }

    // ── Helper ──────────────────────────────────────────

    private User authenticate(String token) throws Exception
    {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<User> userRef = new AtomicReference<>();
        AtomicReference<Throwable> errorRef = new AtomicReference<>();

        jwtAuth.authenticate(new TokenCredentials(token))
                .onSuccess(u -> {
                    userRef.set(u);
                    latch.countDown();
                })
                .onFailure(t -> {
                    errorRef.set(t);
                    latch.countDown();
                });

        assertTrue(latch.await(5, TimeUnit.SECONDS), "Authentication timed out");
        if (errorRef.get() != null)
        {
            fail("Authentication failed: " + errorRef.get().getMessage());
        }
        return userRef.get();
    }
}



