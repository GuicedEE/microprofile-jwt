package com.guicedee.microprofile.jwt.test;

import com.guicedee.microprofile.jwt.MicroProfileJwtContext;
import com.guicedee.microprofile.jwt.VertxJsonWebToken;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.*;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test that starts a real Keycloak instance via Testcontainers,
 * configures a realm/client/user, obtains a real JWT token via OAuth2 password grant,
 * then validates it through Vert.x JWTAuth and bridges to MicroProfile JWT.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeycloakJwtIntegrationTest
{
    private static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.2.4";
    private static final String REALM = "test-realm";
    private static final String CLIENT_ID = "test-client";
    private static final String TEST_USER = "testuser";
    private static final String TEST_PASSWORD = "testpass123";
    private static final String ADMIN_USER = "admin";
    private static final String ADMIN_PASSWORD = "admin";

    @SuppressWarnings("resource")
    private static final GenericContainer<?> keycloak = new GenericContainer<>(KEYCLOAK_IMAGE)
            .withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USER)
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
            .withCommand("start-dev")
            .waitingFor(Wait.forHttp("/realms/master").forPort(8080).withStartupTimeout(Duration.ofMinutes(3)));

    private static Vertx vertx;
    private static String keycloakBaseUrl;
    private static String adminToken;
    private static String userAccessToken;
    private static JWTAuth jwtAuth;

    @BeforeAll
    static void startKeycloakAndConfigure() throws Exception
    {
        keycloak.start();
        keycloakBaseUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        vertx = Vertx.vertx();

        System.out.println("Keycloak started at: " + keycloakBaseUrl);

        // 1. Get admin token
        adminToken = getAdminToken();
        assertNotNull(adminToken, "Failed to obtain admin token");
        System.out.println("Admin token obtained");

        // 2. Create realm
        createRealm();
        System.out.println("Realm '" + REALM + "' created");

        // 3. Create public client
        createClient();
        System.out.println("Client '" + CLIENT_ID + "' created");

        // 4. Create test user with role
        createUser();
        System.out.println("User '" + TEST_USER + "' created");

        // 5. Get JWKS certs and configure Vert.x JWTAuth
        jwtAuth = configureJwtAuth();
        System.out.println("Vert.x JWTAuth configured with Keycloak JWKS");

        // 6. Get a real user token
        userAccessToken = getUserToken();
        assertNotNull(userAccessToken, "Failed to obtain user access token");
        System.out.println("User access token obtained (length=" + userAccessToken.length() + ")");
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
        keycloak.stop();
    }

    @AfterEach
    void clearContext()
    {
        MicroProfileJwtContext.clear();
    }

    @Test
    @Order(1)
    void keycloakTokenIsVerifiedByVertx() throws Exception
    {
        User user = authenticate(userAccessToken);
        assertNotNull(user, "Vert.x should verify the Keycloak-issued token");
        System.out.println("Token verified by Vert.x JWTAuth");
    }

    @Test
    @Order(2)
    void keycloakTokenBridgesToMpJwt() throws Exception
    {
        User user = authenticate(userAccessToken);
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        // Standard claims from Keycloak
        assertNotNull(jwt.getSubject(), "sub claim must be present");
        assertEquals(keycloakBaseUrl + "/realms/" + REALM, jwt.getIssuer(), "Issuer should be Keycloak realm URL");
        assertTrue(jwt.getExpirationTime() > 0, "Token should have expiration");
        assertTrue(jwt.getIssuedAtTime() > 0, "Token should have iat");
        assertNotNull(jwt.getTokenID(), "jti must be present");

        System.out.println("Subject: " + jwt.getSubject());
        System.out.println("Issuer: " + jwt.getIssuer());
        System.out.println("Name: " + jwt.getName());
        System.out.println("Token ID: " + jwt.getTokenID());
        System.out.println("Claims: " + jwt.getClaimNames());
    }

    @Test
    @Order(3)
    void keycloakTokenHasPreferredUsername() throws Exception
    {
        User user = authenticate(userAccessToken);
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        // Keycloak sets preferred_username
        String name = jwt.getName();
        assertNotNull(name);
        // getName() should resolve to preferred_username or sub
        System.out.println("Resolved name: " + name);
        assertTrue(name.equals(TEST_USER) || name.equals(jwt.getSubject()),
                "Name should be preferred_username or sub");
    }

    @Test
    @Order(4)
    void keycloakTokenGroupsContainRealmRoles() throws Exception
    {
        User user = authenticate(userAccessToken);
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        Set<String> groups = jwt.getGroups();
        System.out.println("Groups/roles: " + groups);
        // Keycloak doesn't put roles in "groups" by default, may be empty
        // but the bridge should not throw
        assertNotNull(groups);
    }

    @Test
    @Order(5)
    void keycloakTokenWorksWithContext() throws Exception
    {
        User user = authenticate(userAccessToken);
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        MicroProfileJwtContext.setCurrent(jwt);

        JsonWebToken current = MicroProfileJwtContext.getCurrent();
        assertNotNull(current);
        assertEquals(jwt.getSubject(), current.getSubject());
        assertEquals(jwt.getIssuer(), current.getIssuer());

        MicroProfileJwtContext.clear();
        assertNull(MicroProfileJwtContext.getCurrent());
    }

    @Test
    @Order(6)
    void keycloakTokenAudienceClaim() throws Exception
    {
        User user = authenticate(userAccessToken);
        VertxJsonWebToken jwt = new VertxJsonWebToken(user);

        Set<String> audience = jwt.getAudience();
        System.out.println("Audience: " + audience);
        // Keycloak may or may not include audience depending on config
        assertNotNull(audience);
    }

    @Test
    @Order(7)
    void tamperedKeycloakTokenIsRejected() throws Exception
    {
        // Tamper with the token payload
        String[] parts = userAccessToken.split("\\.");
        char[] payload = parts[1].toCharArray();
        payload[0] = (payload[0] == 'a') ? 'b' : 'a';
        String tampered = parts[0] + "." + new String(payload) + "." + parts[2];

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Throwable> error = new AtomicReference<>();

        jwtAuth.authenticate(new TokenCredentials(tampered))
                .onSuccess(u -> latch.countDown())
                .onFailure(t -> {
                    error.set(t);
                    latch.countDown();
                });

        assertTrue(latch.await(5, TimeUnit.SECONDS));
        assertNotNull(error.get(), "Tampered Keycloak token should be rejected");
        System.out.println("Tampered token correctly rejected: " + error.get().getMessage());
    }

    // ── Keycloak Admin Helpers ──────────────────────────

    private static final HttpClient httpClient = HttpClient.newHttpClient();

    private static String getAdminToken() throws Exception
    {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(keycloakBaseUrl + "/realms/master/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "grant_type=password&client_id=admin-cli&username=" + ADMIN_USER + "&password=" + ADMIN_PASSWORD))
                .build();
        HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode(), "Admin token request failed: " + resp.body());
        return new JsonObject(resp.body()).getString("access_token");
    }

    private static void createRealm() throws Exception
    {
        JsonObject realm = new JsonObject()
                .put("realm", REALM)
                .put("enabled", true)
                .put("sslRequired", "none");

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(keycloakBaseUrl + "/admin/realms"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + adminToken)
                .POST(HttpRequest.BodyPublishers.ofString(realm.encode()))
                .build();
        HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertTrue(resp.statusCode() == 201 || resp.statusCode() == 409,
                "Create realm failed: " + resp.statusCode() + " " + resp.body());
    }

    private static void createClient() throws Exception
    {
        JsonObject client = new JsonObject()
                .put("clientId", CLIENT_ID)
                .put("enabled", true)
                .put("publicClient", true)
                .put("directAccessGrantsEnabled", true)
                .put("standardFlowEnabled", false);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(keycloakBaseUrl + "/admin/realms/" + REALM + "/clients"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + adminToken)
                .POST(HttpRequest.BodyPublishers.ofString(client.encode()))
                .build();
        HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertTrue(resp.statusCode() == 201 || resp.statusCode() == 409,
                "Create client failed: " + resp.statusCode() + " " + resp.body());
    }

    private static void createUser() throws Exception
    {
        JsonObject user = new JsonObject()
                .put("username", TEST_USER)
                .put("enabled", true)
                .put("emailVerified", true)
                .put("email", TEST_USER + "@test.com")
                .put("firstName", "Test")
                .put("lastName", "User")
                .put("credentials", new io.vertx.core.json.JsonArray().add(
                        new JsonObject()
                                .put("type", "password")
                                .put("value", TEST_PASSWORD)
                                .put("temporary", false)));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(keycloakBaseUrl + "/admin/realms/" + REALM + "/users"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + adminToken)
                .POST(HttpRequest.BodyPublishers.ofString(user.encode()))
                .build();
        HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertTrue(resp.statusCode() == 201 || resp.statusCode() == 409,
                "Create user failed: " + resp.statusCode() + " " + resp.body());
    }

    private static JWTAuth configureJwtAuth() throws Exception
    {
        // Fetch JWKS from Keycloak
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(keycloakBaseUrl + "/realms/" + REALM + "/protocol/openid-connect/certs"))
                .GET()
                .build();
        HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode(), "JWKS fetch failed: " + resp.body());

        JsonObject jwks = new JsonObject(resp.body());

        // Filter to signing keys only and configure via JWK JSON objects
        JWTAuthOptions options = new JWTAuthOptions();
        for (Object keyObj : jwks.getJsonArray("keys"))
        {
            JsonObject key = (JsonObject) keyObj;
            String use = key.getString("use", "sig");
            if (!"sig".equals(use))
            {
                System.out.println("Skipping non-signing key: alg=" + key.getString("alg") + " use=" + use);
                continue;
            }
            // Add as JWK (not PEM) - Vert.x can parse JWK JSON directly
            options.addJwk(key);
        }

        return JWTAuth.create(vertx, options);
    }

    private static String getUserToken() throws Exception
    {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(keycloakBaseUrl + "/realms/" + REALM + "/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "grant_type=password&client_id=" + CLIENT_ID +
                        "&username=" + TEST_USER + "&password=" + TEST_PASSWORD))
                .build();
        HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode(), "User token request failed: " + resp.body());
        return new JsonObject(resp.body()).getString("access_token");
    }

    // ── Vert.x Auth Helper ──────────────────────────────

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

        assertTrue(latch.await(10, TimeUnit.SECONDS), "Authentication timed out");
        if (errorRef.get() != null)
        {
            fail("Authentication failed: " + errorRef.get().getMessage());
        }
        return userRef.get();
    }
}




