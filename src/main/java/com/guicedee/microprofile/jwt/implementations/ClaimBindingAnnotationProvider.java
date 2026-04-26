package com.guicedee.microprofile.jwt.implementations;

import com.google.inject.gee.BindingAnnotationProvider;

import java.lang.annotation.Annotation;
import java.util.List;

/**
 * Registers {@code jakarta.inject.Qualifier} as a binding annotation type
 * so that {@code @Claim} (which is meta-annotated with {@code @Qualifier})
 * is recognized by Guice as a valid binding annotation.
 */
public class ClaimBindingAnnotationProvider implements BindingAnnotationProvider
{
    @Override
    public List<Class<? extends Annotation>> getBindingAnnotations()
    {
        return List.of(jakarta.inject.Qualifier.class);
    }
}

