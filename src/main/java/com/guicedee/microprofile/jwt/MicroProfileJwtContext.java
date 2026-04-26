package com.guicedee.microprofile.jwt;

import com.guicedee.client.IGuiceContext;
import com.guicedee.client.scopes.CallScopeProperties;
import com.guicedee.client.scopes.CallScoper;
import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * Request-scoped holder for the current {@link JsonWebToken}.
 * <p>
 * When running inside a Vert.x/GuicedEE {@link CallScoper} (the normal case for HTTP handlers),
 * the token is stored in the {@link CallScopeProperties} map — which is properly scoped
 * per-request even across Mutiny/reactive thread switches within the same call scope.
 * <p>
 * Falls back to a {@code ThreadLocal} when no call scope is active (e.g. unit tests
 * or non-HTTP code paths).
 */
public final class MicroProfileJwtContext
{
    private static final String CALL_SCOPE_KEY = "com.guicedee.microprofile.jwt.current";
    private static final ThreadLocal<JsonWebToken> FALLBACK = new ThreadLocal<>();

    private MicroProfileJwtContext() {}

    /**
     * Sets the current JWT for the active request.
     *
     * @param token the authenticated JsonWebToken, or null to clear
     */
    public static void setCurrent(JsonWebToken token)
    {
        if (token == null)
        {
            clear();
            return;
        }

        CallScopeProperties props = getCallScopeProperties();
        if (props != null)
        {
            props.getProperties().put(CALL_SCOPE_KEY, token);
        }
        else
        {
            FALLBACK.set(token);
        }
    }

    /**
     * Returns the current request's JWT, or null if none is set.
     */
    public static JsonWebToken getCurrent()
    {
        CallScopeProperties props = getCallScopeProperties();
        if (props != null)
        {
            Object value = props.getProperties().get(CALL_SCOPE_KEY);
            if (value instanceof JsonWebToken jwt)
            {
                return jwt;
            }
        }
        return FALLBACK.get();
    }

    /**
     * Clears the current JWT. Call at end of request scope.
     */
    public static void clear()
    {
        CallScopeProperties props = getCallScopeProperties();
        if (props != null)
        {
            props.getProperties().remove(CALL_SCOPE_KEY);
        }
        FALLBACK.remove();
    }

    /**
     * Attempts to retrieve the current CallScopeProperties if a call scope is active.
     *
     * @return the properties, or null if no call scope is active
     */
    private static CallScopeProperties getCallScopeProperties()
    {
        try
        {
            CallScoper scoper = IGuiceContext.get(CallScoper.class);
            if (scoper != null && scoper.isStartedScope())
            {
                return IGuiceContext.get(CallScopeProperties.class);
            }
        }
        catch (Exception _)
        {
            // No injector or no scope active — fall back to ThreadLocal
        }
        return null;
    }
}
