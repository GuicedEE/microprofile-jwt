module com.guicedee.microprofile.jwt.test {
    requires transitive com.guicedee.microprofile.jwt;
    requires org.junit.jupiter.api;
    requires static lombok;
    requires jakarta.json;
    requires io.vertx.auth.jwt;
    requires io.vertx.core;
    requires io.vertx.auth.common;
    requires org.testcontainers;
    requires java.net.http;

    exports com.guicedee.microprofile.jwt.test to com.google.guice;
    opens com.guicedee.microprofile.jwt.test to org.junit.platform.commons, com.google.guice;
}
