package com.guicedee.microprofile.jwt.implementations;

import com.google.inject.AbstractModule;
import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Names;
import com.guicedee.client.IGuiceContext;
import com.guicedee.client.services.lifecycle.IGuiceModule;
import com.guicedee.microprofile.jwt.MicroProfileJwtContext;
import io.github.classgraph.ClassInfo;
import io.github.classgraph.FieldInfo;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.extern.log4j.Log4j2;
import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Guice module that binds MicroProfile JWT types into the GuicedEE injector.
 * <p>
 * Scans for {@link Claim}-annotated fields at startup and creates type-specific
 * bindings using {@code @Named("claimName")} — mirroring the MicroProfile Config
 * pattern where {@code @ConfigProperty} fields are auto-bound.
 * <p>
 * Provides:
 * <ul>
 *   <li>{@link JsonWebToken} — resolved from {@link MicroProfileJwtContext} (request-scoped via ThreadLocal)</li>
 *   <li>{@code @Claim("claimName") String} — for each discovered claim field</li>
 *   <li>{@code @Claim("claimName") Set<String>} — for group/audience claims</li>
 *   <li>{@code @Claim("claimName") Long} — for numeric claims</li>
 *   <li>{@code @Claim("claimName") Optional<T>} — for optional wrappers</li>
 * </ul>
 */
@Log4j2
public class MicroProfileJwtModule extends AbstractModule implements IGuiceModule<MicroProfileJwtModule>
{
    @Override
    protected void configure()
    {
        // Bind JsonWebToken to the context holder
        bind(JsonWebToken.class).toProvider(MicroProfileJwtContext::getCurrent);

        // Scan for @Claim-annotated fields and bind per type
        var classesWithClaim = IGuiceContext.instance()
                                           .getScanResult()
                                           .getClassesWithFieldAnnotation(Claim.class);

        Set<ClassKeyPair> bound = new HashSet<>();

        for (ClassInfo classInfo : classesWithClaim)
        {
            for (FieldInfo fieldInfo : classInfo.getFieldInfo())
            {
                if (fieldInfo.hasAnnotation(Claim.class))
                {
                    Class<?> aClass = classInfo.loadClass();
                    try
                    {
                        Field declaredField = aClass.getDeclaredField(fieldInfo.getName());
                        Claim annotation = declaredField.getAnnotation(Claim.class);
                        String claimName = resolveClaimName(annotation);

                        ClassKeyPair kp = new ClassKeyPair(declaredField.getType(), claimName);
                        if (!bound.contains(kp))
                        {
                            bindClaimField(declaredField, claimName, bound);
                        }
                    }
                    catch (NoSuchFieldException e)
                    {
                        log.warn("Could not resolve field {} on {}: {}", fieldInfo.getName(), classInfo.getName(), e.getMessage());
                    }
                }
            }
        }

        log.info("MicroProfile JWT bindings registered");
    }

    @SuppressWarnings("unchecked")
    private void bindClaimField(Field field, String claimName, Set<ClassKeyPair> bound)
    {
        Class<?> type = field.getType();

        if (String.class.isAssignableFrom(type))
        {
            bound.add(new ClassKeyPair(String.class, claimName));
            bind(String.class).annotatedWith(Names.named(claimName))
                              .toProvider(() -> {
                                  JsonWebToken jwt = MicroProfileJwtContext.getCurrent();
                                  if (jwt == null) return null;
                                  Object val = jwt.getClaim(claimName);
                                  return val != null ? val.toString() : null;
                              });
            bind(Key.get(new TypeLiteral<Optional<String>>()
            {
            }, Names.named(claimName)))
                    .toProvider(() -> {
                        JsonWebToken jwt = MicroProfileJwtContext.getCurrent();
                        if (jwt == null) return Optional.empty();
                        Object val = jwt.getClaim(claimName);
                        return val != null ? Optional.of(val.toString()) : Optional.empty();
                    });
        }
        else if (Set.class.isAssignableFrom(type))
        {
            bound.add(new ClassKeyPair(Set.class, claimName));
            bind(Key.get(new TypeLiteral<Set<String>>()
            {
            }, Names.named(claimName)))
                    .toProvider(() -> {
                        JsonWebToken jwt = MicroProfileJwtContext.getCurrent();
                        if (jwt == null) return Set.of();
                        Object val = jwt.getClaim(claimName);
                        if (val instanceof Set) return (Set<String>) val;
                        if (val instanceof String s) return Set.of(s);
                        return Set.of();
                    });
        }
        else if (Long.class.isAssignableFrom(type) || long.class.isAssignableFrom(type))
        {
            bound.add(new ClassKeyPair(Long.class, claimName));
            bound.add(new ClassKeyPair(long.class, claimName));
            bind(Long.class).annotatedWith(Names.named(claimName))
                            .toProvider(() -> {
                                JsonWebToken jwt = MicroProfileJwtContext.getCurrent();
                                if (jwt == null) return 0L;
                                Object val = jwt.getClaim(claimName);
                                if (val instanceof Number n) return n.longValue();
                                if (val instanceof String s)
                                {
                                    try { return Long.parseLong(s); }
                                    catch (NumberFormatException _) { return 0L; }
                                }
                                return 0L;
                            });
        }
        else if (Integer.class.isAssignableFrom(type) || int.class.isAssignableFrom(type))
        {
            bound.add(new ClassKeyPair(Integer.class, claimName));
            bound.add(new ClassKeyPair(int.class, claimName));
            bind(Integer.class).annotatedWith(Names.named(claimName))
                               .toProvider(() -> {
                                   JsonWebToken jwt = MicroProfileJwtContext.getCurrent();
                                   if (jwt == null) return 0;
                                   Object val = jwt.getClaim(claimName);
                                   if (val instanceof Number n) return n.intValue();
                                   if (val instanceof String s)
                                   {
                                       try { return Integer.parseInt(s); }
                                       catch (NumberFormatException _) { return 0; }
                                   }
                                   return 0;
                               });
        }
        else if (Boolean.class.isAssignableFrom(type) || boolean.class.isAssignableFrom(type))
        {
            bound.add(new ClassKeyPair(Boolean.class, claimName));
            bound.add(new ClassKeyPair(boolean.class, claimName));
            bind(Boolean.class).annotatedWith(Names.named(claimName))
                               .toProvider(() -> {
                                   JsonWebToken jwt = MicroProfileJwtContext.getCurrent();
                                   if (jwt == null) return false;
                                   Object val = jwt.getClaim(claimName);
                                   if (val instanceof Boolean b) return b;
                                   if (val instanceof String s) return Boolean.parseBoolean(s);
                                   return false;
                               });
        }
        else
        {
            // Generic Object binding for any other type
            bound.add(new ClassKeyPair(Object.class, claimName));
            bind(Object.class).annotatedWith(Names.named(claimName))
                              .toProvider(() -> {
                                  JsonWebToken jwt = MicroProfileJwtContext.getCurrent();
                                  if (jwt == null) return null;
                                  return jwt.getClaim(claimName);
                              });
        }
    }

    private String resolveClaimName(Claim annotation)
    {
        if (!annotation.value().isEmpty())
        {
            return annotation.value();
        }
        if (annotation.standard() != Claims.UNKNOWN)
        {
            return annotation.standard().name();
        }
        return annotation.value();
    }

    @Override
    public Integer sortOrder()
    {
        return 95; // after auth providers (90), before general startup
    }

    @EqualsAndHashCode(of = {"clazz", "name"})
    @AllArgsConstructor
    static final class ClassKeyPair
    {
        private final Class<?> clazz;
        private final String name;
    }
}
