package com.guicedee.microprofile.jwt;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;

import java.lang.annotation.Annotation;

/**
 * Runtime implementation of the {@link Claim} annotation for Guice binding keys.
 */
public record ClaimLiteral(String value, Claims standard) implements Claim
{
    public ClaimLiteral(String value)
    {
        this(value, Claims.UNKNOWN);
    }

    @Override
    public Class<? extends Annotation> annotationType()
    {
        return Claim.class;
    }

    @Override
    public int hashCode()
    {
        // As per Annotation spec
        return (127 * "value".hashCode() ^ value.hashCode())
                + (127 * "standard".hashCode() ^ standard.hashCode());
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (!(o instanceof Claim other)) return false;
        return value.equals(other.value()) && standard.equals(other.standard());
    }
}


