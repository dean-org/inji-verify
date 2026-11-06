package io.inji.verify.services.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.dto.verification.TrustRegistryCheckDto;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;

import static org.junit.jupiter.api.Assertions.*;

class TrustRegistryServiceImplTest {

    private static final String ISSUER = "did:web:technoforte.github.io:mosip-did";

    private TrustRegistryServiceImpl service(String location, boolean failOpen) {
        return new TrustRegistryServiceImpl(true, location, 300, failOpen, new DefaultResourceLoader(), new ObjectMapper());
    }

    private String vc(String issuer, String type, String verificationMethod) {
        return "{\"issuer\":\"" + issuer + "\",\"type\":[\"VerifiableCredential\",\"" + type + "\"],"
                + "\"proof\":{\"verificationMethod\":\"" + verificationMethod + "\"}}";
    }

    @Test
    void trustsListedActiveIssuerWithAllowedType() {
        TrustRegistryCheckDto r = service("classpath:trust-registry/trusted-issuers.json", false)
                .check(vc(ISSUER, "AgriculturalProducerCredential", ISSUER + "#key-1"), CredentialFormat.LDP_VC);
        assertTrue(r.isTrusted());
        assertNotNull(r.getIssuerName());
    }

    @Test
    void rejectsUnlistedIssuer() {
        TrustRegistryCheckDto r = service("classpath:trust-registry/trusted-issuers.json", false)
                .check(vc("did:web:evil.example", "AgriculturalProducerCredential", "did:web:evil.example#k"), CredentialFormat.LDP_VC);
        assertFalse(r.isTrusted());
        assertEquals("ISSUER_NOT_TRUSTED", r.getError().getErrorCode());
    }

    @Test
    void rejectsDisallowedCredentialType() {
        TrustRegistryCheckDto r = service("classpath:trust-registry/trusted-issuers.json", false)
                .check(vc(ISSUER, "DrivingLicense", ISSUER + "#key-1"), CredentialFormat.LDP_VC);
        assertFalse(r.isTrusted());
        assertEquals("CREDENTIAL_TYPE_NOT_ALLOWED", r.getError().getErrorCode());
    }

    @Test
    void rejectsSigningKeyFromDifferentDid() {
        TrustRegistryCheckDto r = service("classpath:trust-registry/trusted-issuers.json", false)
                .check(vc(ISSUER, "AgriculturalProducerCredential", "did:web:evil.example#k"), CredentialFormat.LDP_VC);
        assertFalse(r.isTrusted());
        assertEquals("SIGNING_KEY_ISSUER_MISMATCH", r.getError().getErrorCode());
    }

    @Test
    void failsClosedWhenRegistryUnavailable() {
        TrustRegistryCheckDto r = service("file:/does/not/exist.json", false)
                .check(vc(ISSUER, "AgriculturalProducerCredential", ISSUER + "#key-1"), CredentialFormat.LDP_VC);
        assertFalse(r.isTrusted());
        assertEquals("TRUST_REGISTRY_UNAVAILABLE", r.getError().getErrorCode());
    }

    @Test
    void failOpenTrustsWhenRegistryUnavailable() {
        assertTrue(service("file:/does/not/exist.json", true)
                .check(vc(ISSUER, "AgriculturalProducerCredential", ISSUER + "#key-1"), CredentialFormat.LDP_VC).isTrusted());
    }
}
