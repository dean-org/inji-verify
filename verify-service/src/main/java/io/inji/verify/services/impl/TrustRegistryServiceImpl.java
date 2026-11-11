package io.inji.verify.services.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBORObject;
import io.inji.verify.dto.core.ErrorDto;
import io.inji.verify.dto.verification.TrustRegistryCheckDto;
import io.inji.verify.services.TrustRegistryService;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Service
public class TrustRegistryServiceImpl implements TrustRegistryService {

    public static final String ERR_ISSUER_NOT_TRUSTED = "ISSUER_NOT_TRUSTED";
    public static final String ERR_ISSUER_INACTIVE = "ISSUER_NOT_ACTIVE";
    public static final String ERR_TYPE_NOT_ALLOWED = "CREDENTIAL_TYPE_NOT_ALLOWED";
    public static final String ERR_KEY_ISSUER_MISMATCH = "SIGNING_KEY_ISSUER_MISMATCH";
    public static final String ERR_ISSUER_MISSING = "ISSUER_NOT_FOUND_IN_CREDENTIAL";
    public static final String ERR_REGISTRY_UNAVAILABLE = "TRUST_REGISTRY_UNAVAILABLE";

    record IssuerEntry(String id, String name, String status, Set<String> credentialTypes,
                       Instant validFrom, Instant validUntil) {}

    private record CachedRegistry(Map<String, IssuerEntry> issuers, Instant loadedAt) {}

    private record CredentialInfo(String issuer, List<String> types, String verificationMethod) {}

    /** failure == null means the issuer passed the registry lookup. */
    private record Decision(TrustRegistryCheckDto failure, String issuerName) {}

    private record CachedAuthorisation(boolean authorised, Instant loadedAt) {}

    private final boolean enabled;
    private final String mode;                 // "file" (JSON file / URL) or "api" (trust registry REST API)
    private final String location;
    private final Duration cacheTtl;
    private final boolean failOpen;
    private final String apiBaseUrl;
    private final Duration apiTimeout;
    private final String apiCwtCredentialType;
    private final String apiAuthHeader;        // "Basic ..." or null when the API needs no login
    private final ResourceLoader resourceLoader;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final AtomicReference<CachedRegistry> cache = new AtomicReference<>();
    private final Map<String, CachedAuthorisation> apiCache = new ConcurrentHashMap<>();

    @Autowired
    public TrustRegistryServiceImpl(
            @Value("${inji.verify.trust-registry.enabled:false}") boolean enabled,
            @Value("${inji.verify.trust-registry.mode:file}") String mode,
            @Value("${inji.verify.trust-registry.location:classpath:trust-registry/trusted-issuers.json}") String location,
            @Value("${inji.verify.trust-registry.cache-ttl-seconds:300}") long cacheTtlSeconds,
            @Value("${inji.verify.trust-registry.fail-open:false}") boolean failOpen,
            @Value("${inji.verify.trust-registry.api.base-url:}") String apiBaseUrl,
            @Value("${inji.verify.trust-registry.api.timeout-seconds:5}") long apiTimeoutSeconds,
            @Value("${inji.verify.trust-registry.api.cwt-credential-type:}") String apiCwtCredentialType,
            @Value("${inji.verify.trust-registry.api.username:}") String apiUsername,
            @Value("${inji.verify.trust-registry.api.password:}") String apiPassword,
            ResourceLoader resourceLoader,
            ObjectMapper objectMapper) {
        this.enabled = enabled;
        this.mode = mode == null ? "file" : mode.trim().toLowerCase();
        this.location = location;
        this.cacheTtl = Duration.ofSeconds(cacheTtlSeconds);
        this.failOpen = failOpen;
        this.apiBaseUrl = apiBaseUrl == null ? "" : apiBaseUrl.trim().replaceAll("/+$", "");
        this.apiTimeout = Duration.ofSeconds(apiTimeoutSeconds);
        this.apiCwtCredentialType = apiCwtCredentialType == null ? "" : apiCwtCredentialType.trim();
        this.apiAuthHeader = (apiUsername == null || apiUsername.isBlank()) ? null
                : "Basic " + Base64.getEncoder().encodeToString(
                        (apiUsername + ":" + (apiPassword == null ? "" : apiPassword)).getBytes(StandardCharsets.UTF_8));
        this.resourceLoader = resourceLoader;
        this.objectMapper = objectMapper;
    }

    /** Convenience constructor for file mode (used by tests). */
    public TrustRegistryServiceImpl(boolean enabled, String location, long cacheTtlSeconds, boolean failOpen,
                                    ResourceLoader resourceLoader, ObjectMapper objectMapper) {
        this(enabled, "file", location, cacheTtlSeconds, failOpen, "", 5, "", "", "", resourceLoader, objectMapper);
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public TrustRegistryCheckDto check(String credential, CredentialFormat format) {
        CredentialInfo info;
        try {
            info = extractCredentialInfo(credential, format);
        } catch (Exception e) {
            log.error("Unable to read issuer details from credential for trust registry check", e);
            return untrusted(null, null, ERR_ISSUER_MISSING, "Could not read the issuer from the credential.");
        }
        if (info.issuer() == null || info.issuer().isBlank()) {
            return untrusted(null, null, ERR_ISSUER_MISSING, "Credential does not contain an issuer.");
        }
        log.debug("Trust registry check: mode={}, issuer={}, types={}", mode, info.issuer(), info.types());

        Decision decision = "api".equals(mode) ? decideViaApi(info) : decideViaFile(info, format);
        if (decision.failure() != null) {
            return decision.failure();
        }

        // The signature was verified against the key in verificationMethod. Make sure that key belongs to the
        // trusted issuer, otherwise anyone could claim a trusted "issuer" value but sign with their own DID.
        String vm = info.verificationMethod();
        if (vm != null && vm.startsWith("did:")) {
            String vmDid = vm.contains("#") ? vm.substring(0, vm.indexOf('#')) : vm;
            if (!vmDid.equals(info.issuer())) {
                return untrusted(info.issuer(), decision.issuerName(), ERR_KEY_ISSUER_MISMATCH, "Signing key does not belong to the issuer.");
            }
        }

        return new TrustRegistryCheckDto(true, info.issuer(), decision.issuerName(), null);
    }

    // ---------------------------------------------------------------- mode: file / URL registry

    private Decision decideViaFile(CredentialInfo info, CredentialFormat format) {
        Map<String, IssuerEntry> registry;
        try {
            registry = getRegistry();
        } catch (Exception e) {
            log.error("Trust registry could not be loaded from {}", location, e);
            return registryUnavailable(info);
        }

        IssuerEntry entry = registry.get(info.issuer());
        if (entry == null) {
            return fail(untrusted(info.issuer(), null, ERR_ISSUER_NOT_TRUSTED, "Issuer is not listed in the trust registry."));
        }

        Instant now = Instant.now();
        boolean active = "active".equalsIgnoreCase(entry.status())
                && (entry.validFrom() == null || !now.isBefore(entry.validFrom()))
                && (entry.validUntil() == null || now.isBefore(entry.validUntil()));
        if (!active) {
            return fail(untrusted(info.issuer(), entry.name(), ERR_ISSUER_INACTIVE, "Issuer is suspended, revoked or outside its validity period."));
        }

        Set<String> allowedTypes = entry.credentialTypes();
        Set<String> actualTypes = new HashSet<>(info.types());
        actualTypes.remove("VerifiableCredential");

        // CWT credentials carry no type list, so the type restriction cannot be applied to them;
        // the issuer must still be listed and active. LDP / SD-JWT keep the strict check.
        boolean typeCheckApplicable = format != CredentialFormat.CWT_VC;
        if (typeCheckApplicable && (allowedTypes == null || allowedTypes.isEmpty()
                || Collections.disjoint(allowedTypes, actualTypes))) {
            log.warn("Credential type validation failed. Issuer={}, AllowedTypes={}, ActualTypes={}",
                    info.issuer(), allowedTypes, actualTypes);
            return fail(untrusted(info.issuer(), entry.name(), ERR_TYPE_NOT_ALLOWED, "Issuer is not authorised to issue this credential type."));
        }
        return new Decision(null, entry.name());
    }

    // ---------------------------------------------------------------- mode: trust registry REST API

    private Decision decideViaApi(CredentialInfo info) {
        if (apiBaseUrl.isBlank()) {
            log.error("Trust registry mode is 'api' but inji.verify.trust-registry.api.base-url is not set");
            return registryUnavailable(info);
        }

        List<String> typesToCheck = new ArrayList<>(info.types());
        typesToCheck.remove("VerifiableCredential");
        // CWT credentials have no type; fall back to the configured type (if any).
        if (typesToCheck.isEmpty() && !apiCwtCredentialType.isBlank()) {
            typesToCheck.add(apiCwtCredentialType);
        }
        if (typesToCheck.isEmpty()) {
            return fail(untrusted(info.issuer(), null, ERR_TYPE_NOT_ALLOWED,
                    "Credential has no type to check against the trust registry."));
        }

        try {
            for (String type : typesToCheck) {
                if (isAuthorisedViaApi(info.issuer(), type)) {
                    return new Decision(null, null);
                }
            }
            return fail(untrusted(info.issuer(), null, ERR_ISSUER_NOT_TRUSTED,
                    "Issuer is not authorised for this credential type in the trust registry."));
        } catch (Exception e) {
            log.error("Trust registry API call failed", e);
            return registryUnavailable(info);
        }
    }

    private boolean isAuthorisedViaApi(String issuer, String credentialType) throws Exception {
        String key = issuer + "|" + credentialType;
        CachedAuthorisation cached = apiCache.get(key);
        if (cached != null && Instant.now().isBefore(cached.loadedAt().plus(cacheTtl))) {
            return cached.authorised();
        }

        URI uri = URI.create(apiBaseUrl + "/v1/authorizations/check"
                + "?issuerId=" + URLEncoder.encode(issuer, StandardCharsets.UTF_8)
                + "&credentialType=" + URLEncoder.encode(credentialType, StandardCharsets.UTF_8));
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(uri)
                .timeout(apiTimeout)
                .header("Accept", "application/json");
        if (apiAuthHeader != null) {
            requestBuilder.header("Authorization", apiAuthHeader);
        }
        HttpRequest request = requestBuilder.GET().build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Trust registry API responded with HTTP " + response.statusCode());
        }

        JsonNode root = objectMapper.readTree(response.body());
        JsonNode node = root.has("authorised") ? root.get("authorised") : root.path("data").path("authorised");
        // A technical failure never carries an 'authorised' field, so a missing field is an error, not a "no".
        if (!node.isBoolean()) {
            throw new IllegalStateException("Trust registry API response has no 'authorised' field");
        }

        boolean authorised = node.asBoolean();
        if (apiCache.size() > 1000) apiCache.clear();
        apiCache.put(key, new CachedAuthorisation(authorised, Instant.now()));
        log.debug("Trust registry API: issuer={}, type={}, authorised={}", issuer, credentialType, authorised);
        return authorised;
    }

    // ---------------------------------------------------------------- shared helpers

    private Decision fail(TrustRegistryCheckDto failure) {
        return new Decision(failure, null);
    }

    private Decision registryUnavailable(CredentialInfo info) {
        if (failOpen) {
            log.warn("Trust registry unavailable, fail-open is ON, treating issuer {} as trusted", info.issuer());
            return new Decision(null, null);
        }
        return fail(untrusted(info.issuer(), null, ERR_REGISTRY_UNAVAILABLE, "Trust registry is not reachable."));
    }

    private TrustRegistryCheckDto untrusted(String issuer, String name, String code, String message) {
        log.info("Trust registry check failed for issuer {}: {}", issuer, code);
        return new TrustRegistryCheckDto(false, issuer, name, new ErrorDto(code, message));
    }

    // ---------------------------------------------------------------- registry loading

    private Map<String, IssuerEntry> getRegistry() throws Exception {
        CachedRegistry current = cache.get();
        if (current != null && Instant.now().isBefore(current.loadedAt().plus(cacheTtl))) {
            return current.issuers();
        }
        try {
            Map<String, IssuerEntry> loaded = parseRegistry(readRegistry());
            log.debug("Trust registry loaded from: {}", location);
            log.debug("Trust registry issuer entries: {}", loaded);
            cache.set(new CachedRegistry(loaded, Instant.now()));
            return loaded;
        } catch (Exception e) {
            if (current != null) {
                log.warn("Refreshing trust registry failed, using last known copy", e);
                return current.issuers();
            }
            throw e;
        }
    }

    private String readRegistry() throws Exception {
        if (location.startsWith("http://") || location.startsWith("https://")) {
            HttpRequest request = HttpRequest.newBuilder(URI.create(location)).timeout(Duration.ofSeconds(5)).GET().build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Trust registry responded with HTTP " + response.statusCode());
            }
            return response.body();
        }
        Resource resource = resourceLoader.getResource(location);
        try (InputStream in = resource.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private Map<String, IssuerEntry> parseRegistry(String json) throws Exception {
        JsonNode root = objectMapper.readTree(json);
        JsonNode issuers = root.path("issuers");
        if (!issuers.isArray()) {
            throw new IllegalStateException("Trust registry has no 'issuers' array");
        }
        Map<String, IssuerEntry> result = new HashMap<>();
        for (JsonNode node : issuers) {
            String id = node.path("id").asText(null);
            if (id == null || id.isBlank()) continue;
            Set<String> types = new HashSet<>();
            node.path("credentialTypes").forEach(t -> types.add(t.asText()));
            result.put(id, new IssuerEntry(
                    id,
                    node.path("name").asText(null),
                    node.path("status").asText("active"),
                    types,
                    parseInstant(node.path("validFrom").asText(null)),
                    parseInstant(node.path("validUntil").asText(null))));
        }
        return result;
    }

    private static Instant parseInstant(String value) {
        return (value == null || value.isBlank()) ? null : Instant.parse(value);
    }

    // ---------------------------------------------------------------- credential parsing

    private CredentialInfo extractCredentialInfo(String credential, CredentialFormat format) {
        return switch (format) {
            case VC_SD_JWT, DC_SD_JWT -> fromSdJwt(credential);
            case CWT_VC -> fromCwt(credential);
            default -> fromLdp(credential);
        };
    }

    private CredentialInfo fromLdp(String credential) {
        JSONObject vc = new JSONObject(credential);
        Object issuerObj = vc.opt("issuer");
        String issuer = issuerObj instanceof JSONObject o ? o.optString("id", null)
                : issuerObj instanceof String s ? s : null;

        List<String> types = new ArrayList<>();
        Object typeObj = vc.opt("type");
        if (typeObj instanceof JSONArray arr) {
            arr.forEach(t -> types.add(String.valueOf(t)));
        } else if (typeObj instanceof String s) {
            types.add(s);
        }

        Object proofObj = vc.opt("proof");
        JSONObject proof = proofObj instanceof JSONArray arr && !arr.isEmpty() ? arr.optJSONObject(0)
                : proofObj instanceof JSONObject o ? o : null;
        String vm = proof != null ? proof.optString("verificationMethod", null) : null;
        return new CredentialInfo(issuer, types, vm);
    }

    private CredentialInfo fromSdJwt(String credential) {
        String[] parts = credential.split("~")[0].split("\\.");
        JSONObject header = new JSONObject(new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8));
        JSONObject payload = new JSONObject(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
        String vct = payload.optString("vct", null);
        return new CredentialInfo(payload.optString("iss", null),
                vct == null ? List.of() : List.of(vct),
                header.optString("kid", null));
    }

    private CredentialInfo fromCwt(String credential) {
        byte[] bytes = HexFormat.of().parseHex(credential.replaceAll("\\s", ""));
        CBORObject cwt = CBORObject.DecodeFromBytes(bytes);
        CBORObject claims = CBORObject.DecodeFromBytes(cwt.get(2).GetByteString());
        CBORObject iss = claims.get(CBORObject.FromObject(1));
        return new CredentialInfo(iss != null ? iss.AsString() : null, List.of(), null);
    }
}
