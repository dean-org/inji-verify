package io.inji.verify.dto.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.dto.core.ErrorDto;
import io.mosip.vercred.vcverifier.data.VerificationStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class VCVerificationStatusDtoTest {
    @Test
    public void shouldTestConstructor() {
        VCVerificationStatusDto successDto = new  VCVerificationStatusDto(VerificationStatus.SUCCESS);
        assertEquals(VerificationStatus.SUCCESS, successDto.getVerificationStatus());

        VCVerificationStatusDto expiredDto = new  VCVerificationStatusDto(VerificationStatus.EXPIRED);
        assertEquals(VerificationStatus.EXPIRED, expiredDto.getVerificationStatus());

        VCVerificationStatusDto invalidDto = new  VCVerificationStatusDto(VerificationStatus.INVALID);
        assertEquals(VerificationStatus.INVALID, invalidDto.getVerificationStatus());
    }

    @Test
    public void shouldSerializeUntrustedIssuerAsVerificationStatus() throws Exception {
        TrustRegistryCheckDto untrusted = new TrustRegistryCheckDto(false, "did:web:x", null,
                new ErrorDto("ISSUER_NOT_TRUSTED", "Issuer is not listed in the trust registry."));
        JsonNode json = new ObjectMapper().readTree(
                new ObjectMapper().writeValueAsString(new VCVerificationStatusDto(VerificationStatus.INVALID, untrusted)));

        assertEquals("UNTRUSTED_ISSUER", json.get("verificationStatus").asText());
        assertEquals("INVALID", json.get("rawVerificationStatus").asText());
        assertFalse(json.get("trustRegistryCheck").get("trusted").asBoolean());
    }

    @Test
    public void shouldSerializePlainStatusWhenNoTrustCheck() throws Exception {
        JsonNode json = new ObjectMapper().readTree(
                new ObjectMapper().writeValueAsString(new VCVerificationStatusDto(VerificationStatus.EXPIRED)));
        assertEquals("EXPIRED", json.get("verificationStatus").asText());
    }
}
