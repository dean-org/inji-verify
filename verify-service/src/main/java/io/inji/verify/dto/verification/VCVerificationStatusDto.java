package io.inji.verify.dto.verification;

import io.mosip.vercred.vcverifier.data.VerificationStatus;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class VCVerificationStatusDto {
    VerificationStatus verificationStatus;
    /** Null when the trust registry check is disabled or was not applicable. */
    TrustRegistryCheckDto trustRegistryCheck;

    public VCVerificationStatusDto(VerificationStatus verificationStatus) {
        this(verificationStatus, null);
    }
}
