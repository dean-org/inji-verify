package io.inji.verify.dto.verification;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.vercred.vcverifier.data.VerificationStatus;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class VCVerificationStatusDto {

    /** Result of the credential checks (signature, expiry, revocation). Sent as "rawVerificationStatus". */
    @JsonProperty("rawVerificationStatus")
    VerificationStatus verificationStatus;

    /** Null when the trust registry check is disabled or was not applicable. */
    TrustRegistryCheckDto trustRegistryCheck;

    public VCVerificationStatusDto(VerificationStatus verificationStatus) {
        this(verificationStatus, null);
    }

    /**
     * The "verificationStatus" API clients read (the Inji Verify SDK passes it straight to the UI).
     * It is "UNTRUSTED_ISSUER" when the credential is genuine but the issuer failed the trust registry check.
     * Any client that only accepts "SUCCESS" still fails safe.
     */
    @JsonProperty("verificationStatus")
    public String getClientVerificationStatus() {
        if (trustRegistryCheck != null && !trustRegistryCheck.isTrusted()) {
            return "UNTRUSTED_ISSUER";
        }
        return verificationStatus == null ? null : verificationStatus.name();
    }
}
