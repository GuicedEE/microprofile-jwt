import com.guicedee.client.services.lifecycle.IGuiceModule;
import com.guicedee.client.services.lifecycle.IGuicePreStartup;
import com.guicedee.microprofile.jwt.implementations.*;

module com.guicedee.microprofile.jwt {
    requires transitive com.guicedee.vertx;
    requires transitive com.guicedee.guicedinjection;
    requires transitive io.vertx.auth.jwt; // optional at runtime — accessed via reflection when present

    requires static lombok;
    requires io.github.classgraph;

    exports com.guicedee.microprofile.jwt;
    exports com.guicedee.microprofile.jwt.implementations;

    // MP JWT API re-export
    requires transitive microprofile.jwt.auth.api;
    requires transitive jakarta.json;

    opens com.guicedee.microprofile.jwt to com.google.guice, com.guicedee.client, com.guicedee.guicedinjection, com.fasterxml.jackson.databind;
    opens com.guicedee.microprofile.jwt.implementations to com.google.guice, com.guicedee.client, com.guicedee.guicedinjection;

    provides IGuiceModule with MicroProfileJwtModule;
    provides IGuicePreStartup with MicroProfileJwtPreStartup;

    // SPI registrations for @Claim as injectable annotation
    provides com.google.inject.gee.InjectionPointProvider with ClaimInjectionPointProvider;
    provides com.google.inject.gee.NamedAnnotationProvider with ClaimNamedAnnotationProvider;
    provides com.google.inject.gee.BindingAnnotationProvider with ClaimBindingAnnotationProvider;
}


