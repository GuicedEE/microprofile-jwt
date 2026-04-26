package com.guicedee.microprofile.jwt.implementations;

import com.guicedee.client.services.lifecycle.IGuicePreStartup;
import com.guicedee.microprofile.jwt.MicroProfileJwtContext;
import com.guicedee.microprofile.jwt.VertxJsonWebToken;
import io.vertx.ext.auth.User;
import io.vertx.core.Future;
import lombok.extern.log4j.Log4j2;

import java.util.List;

/**
 * Pre-startup hook that validates the JWT auth provider is available
 * for the MicroProfile JWT bridge.
 * <p>
 * The actual request-scoped population of {@link MicroProfileJwtContext}
 * should be performed by the route handler or filter that authenticates
 * the user. A typical pattern:
 *
 * <pre>
 * User user = routingContext.user();
 * if (user != null) {
 *     MicroProfileJwtContext.setCurrent(new VertxJsonWebToken(user));
 * }
 * // ... handle request ...
 * MicroProfileJwtContext.clear();
 * </pre>
 *
 * This pre-startup checks whether the GuicedEE JWT authentication provider
 * is available and configured. The auth provider classes are accessed via
 * reflection to keep them optional — this module works without the auth
 * providers being on the module path.
 */
@Log4j2
public class MicroProfileJwtPreStartup implements IGuicePreStartup<MicroProfileJwtPreStartup>
{
    @Override
    public List<Future<Boolean>> onStartup()
    {
        try
        {
            Class<?> providerClass = Class.forName("com.guicedee.vertx.auth.jwt.JwtAuthenticationProvider");
            Object jwtAuth = providerClass.getMethod("getJwtAuth").invoke(null);
            if (jwtAuth != null)
            {
                log.info("MicroProfile JWT bridge activated - Vert.x JWTAuth provider is available");
            }
            else
            {
                log.debug("MicroProfile JWT bridge: no JWTAuth provider found yet - " +
                        "ensure @JwtAuthOptions is configured for JWT authentication");
            }
        }
        catch (ClassNotFoundException _)
        {
            log.debug("MicroProfile JWT bridge: JwtAuthenticationProvider not on module path - " +
                    "JWT auth provider integration is optional");
        }
        catch (Exception e)
        {
            log.debug("MicroProfile JWT bridge: could not check JwtAuthenticationProvider - {}", e.getMessage());
        }
        return List.of();
    }

    /**
     * Convenience method to create a {@link VertxJsonWebToken} from a Vert.x User
     * and set it as the current request context.
     *
     * @param user the authenticated Vert.x user
     */
    public static void setCurrentUser(User user)
    {
        if (user != null)
        {
            MicroProfileJwtContext.setCurrent(new VertxJsonWebToken(user));
        }
        else
        {
            MicroProfileJwtContext.clear();
        }
    }

    @Override
    public Integer sortOrder()
    {
        return 150; // run after auth providers have initialized
    }
}
