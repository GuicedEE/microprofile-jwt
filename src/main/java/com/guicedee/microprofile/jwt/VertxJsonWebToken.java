package com.guicedee.microprofile.jwt;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import lombok.Getter;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.util.*;

/**
 * Bridge implementation of {@link JsonWebToken} backed by a Vert.x {@link User}.
 * <p>
 * Extracts MP JWT standard claims from the Vert.x User principal and attributes,
 * providing a seamless bridge between the MicroProfile JWT specification and the
 * Vert.x auth JWT provider used by GuicedEE.
 * <p>
 * Claims are resolved from the Vert.x User's {@code principal()} JSON object and
 * the {@code accessToken} attribute (if present).
 */
public class VertxJsonWebToken implements JsonWebToken
{
    @Getter
    private final User vertxUser;
    private final JsonObject principal;
    private final JsonObject accessToken;

    /**
     * Creates a new MP JWT bridge from a Vert.x User.
     *
     * @param vertxUser the authenticated Vert.x user (must not be null)
     */
    public VertxJsonWebToken(User vertxUser)
    {
        this.vertxUser = vertxUser;
        this.principal = vertxUser.principal() != null ? vertxUser.principal() : new JsonObject();
        this.accessToken = vertxUser.attributes() != null && vertxUser.attributes().containsKey("accessToken")
                ? vertxUser.attributes().getJsonObject("accessToken")
                : principal;
    }

    @Override
    public String getName()
    {
        // MP JWT spec: "upn" → "preferred_username" → "sub"
        String upn = claimString(Claims.upn);
        if (upn != null && !upn.isBlank()) return upn;

        String preferredUsername = stringClaim("preferred_username");
        if (preferredUsername != null && !preferredUsername.isBlank()) return preferredUsername;

        return getSubject();
    }

    @Override
    public Set<String> getClaimNames()
    {
        Set<String> names = new LinkedHashSet<>(accessToken.fieldNames());
        names.addAll(principal.fieldNames());
        return Collections.unmodifiableSet(names);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T getClaim(String claimName)
    {
        if (claimName == null) return null;

        // Check access token first, then principal
        Object value = accessToken.getValue(claimName);
        if (value == null)
        {
            value = principal.getValue(claimName);
        }
        if (value == null) return null;

        // Convert Vert.x JSON types to MP JWT expected types
        if (value instanceof JsonArray jsonArray)
        {
            return (T) jsonArrayToSet(jsonArray);
        }
        if (value instanceof JsonObject jsonObject)
        {
            return (T) jsonObject.getMap();
        }
        return (T) value;
    }

    // ── Standard MP JWT Claims ──────────────────────────

    @Override
    public String getRawToken()
    {
        return stringClaim("raw_token");
    }

    @Override
    public String getIssuer()
    {
        return claimString(Claims.iss);
    }

    @Override
    public Set<String> getAudience()
    {
        Object aud = getClaim(Claims.aud.name());
        if (aud instanceof Set) return (Set<String>) aud;
        if (aud instanceof String s) return Set.of(s);
        return Collections.emptySet();
    }

    @Override
    public String getSubject()
    {
        return claimString(Claims.sub);
    }

    @Override
    public String getTokenID()
    {
        return claimString(Claims.jti);
    }

    @Override
    public long getExpirationTime()
    {
        return longClaim(Claims.exp);
    }

    @Override
    public long getIssuedAtTime()
    {
        return longClaim(Claims.iat);
    }

    @Override
    public Set<String> getGroups()
    {
        Object groups = getClaim(Claims.groups.name());
        if (groups instanceof Set) return (Set<String>) groups;
        if (groups instanceof String s) return Set.of(s);
        return Collections.emptySet();
    }

    // ── Helpers ─────────────────────────────────────────

    private String claimString(Claims c)
    {
        return stringClaim(c.name());
    }

    private String stringClaim(String name)
    {
        Object v = getClaim(name);
        return v != null ? v.toString() : null;
    }

    private long longClaim(Claims c)
    {
        Object v = getClaim(c.name());
        if (v instanceof Number n) return n.longValue();
        if (v instanceof String s)
        {
            try { return Long.parseLong(s); }
            catch (NumberFormatException _) { return 0L; }
        }
        return 0L;
    }

    private Set<String> jsonArrayToSet(JsonArray array)
    {
        Set<String> result = new LinkedHashSet<>(array.size());
        for (int i = 0; i < array.size(); i++)
        {
            Object item = array.getValue(i);
            if (item != null) result.add(item.toString());
        }
        return Collections.unmodifiableSet(result);
    }
}






