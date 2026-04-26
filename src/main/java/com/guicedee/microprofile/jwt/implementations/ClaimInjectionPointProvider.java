package com.guicedee.microprofile.jwt.implementations;

import com.google.inject.gee.InjectionPointProvider;
import org.eclipse.microprofile.jwt.Claim;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;

/**
 * Registers {@link Claim} as an injection point annotation so that
 * fields annotated with {@code @Claim("sub")} are treated as Guice
 * injection points without requiring an explicit {@code @Inject}.
 */
public class ClaimInjectionPointProvider implements InjectionPointProvider
{
    @Override
    public Class<? extends Annotation> injectionPoint(AnnotatedElement member)
    {
        return Claim.class;
    }
}

