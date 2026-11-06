package io.inji.verify.dto.submission;

import io.inji.verify.dto.verification.TrustRegistryCheckDto;
import io.mosip.vercred.vcverifier.data.VerificationStatus;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class VCSubmissionVerificationStatusDto {
    private String vc;
    private VerificationStatus verificationStatus;
    private TrustRegistryCheckDto trustRegistryCheck;

    public VCSubmissionVerificationStatusDto(String vc, VerificationStatus verificationStatus) {
        this(vc, verificationStatus, null);
    }
}
