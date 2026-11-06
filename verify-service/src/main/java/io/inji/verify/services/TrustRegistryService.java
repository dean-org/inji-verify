package io.inji.verify.services;

import io.inji.verify.dto.verification.TrustRegistryCheckDto;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;

public interface TrustRegistryService {

    /** @return true when the trust registry check is switched on via configuration. */
    boolean isEnabled();

    /**
     * Checks that the issuer of the given credential is listed (and active) in the trust registry,
     * is allowed to issue this credential type, and that the signing key belongs to that issuer.
     * Must be called only after the cryptographic verification succeeded.
     */
    TrustRegistryCheckDto check(String credential, CredentialFormat format);
}
