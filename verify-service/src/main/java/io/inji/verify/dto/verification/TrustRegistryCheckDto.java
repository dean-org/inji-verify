package io.inji.verify.dto.verification;

import io.inji.verify.dto.core.ErrorDto;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Result of checking the credential issuer against the configured trust registry.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class TrustRegistryCheckDto {
    private boolean trusted;
    private String issuer;
    private String issuerName;
    private ErrorDto error;
}
