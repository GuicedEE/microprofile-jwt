package com.guicedee.microprofile.jwt.implementations;

import com.google.inject.gee.NamedAnnotationProvider;
import com.google.inject.name.Named;
import com.google.inject.name.Names;
import org.eclipse.microprofile.jwt.Claim;

import java.lang.annotation.Annotation;

/**
 * Converts {@code @Claim("sub")} annotations into Guice {@code @Named("sub")}
 * bindings so that the claim name is used as the Guice binding key.
 */
public class ClaimNamedAnnotationProvider implements NamedAnnotationProvider
{
    @Override
    public Named getNamedAnnotation(Annotation annotation)
    {
        if (annotation instanceof Claim claim)
        {
            String name = claim.value();
            if (name.isEmpty())
            {
                name = claim.standard().name();
            }
            return Names.named(name);
        }
        return null;
    }

    @Override
    public Named getNamedAnnotation(Class<? extends Annotation> annotationType)
    {
        if (annotationType == Claim.class)
        {
            return Names.named("claim");
        }
        return null;
    }
}

