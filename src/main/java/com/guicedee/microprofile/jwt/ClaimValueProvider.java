package com.guicedee.microprofile.jwt;

import com.google.inject.Provider;
import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * Guice provider for individual JWT claim values.
 * <p>
 * Resolves the claim from the current call-scoped {@link JsonWebToken} at injection time.
 *
 * @param <T> the claim type
 */
public class ClaimValueProvider<T> implements Provider<T>
{
    private final Provider<JsonWebToken> jwtProvider;
    private final String claimName;

    public ClaimValueProvider(Provider<JsonWebToken> jwtProvider, String claimName)
    {
        this.jwtProvider = jwtProvider;
        this.claimName = claimName;
    }

    @Override
    @SuppressWarnings("unchecked")
    public T get()
    {
        JsonWebToken jwt = jwtProvider.get();
        if (jwt == null) return null;
        return (T) jwt.getClaim(claimName);
    }
}

