package com.guicedee.microprofile.jwt.test;

import lombok.Getter;
import lombok.Setter;
import org.eclipse.microprofile.jwt.Claim;

import java.util.Set;

/**
 * Test class with @Claim-annotated fields — no @Inject needed.
 */
@Getter
@Setter
public class ClaimTarget
{
    @Claim("sub")
    private String subject;

    @Claim("iss")
    private String issuer;

    @Claim("groups")
    private Set<String> groups;

    @Claim("exp")
    private long expiration;

    @Claim("custom_claim")
    private String customClaim;
}

