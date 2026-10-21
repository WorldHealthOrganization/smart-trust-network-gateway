package eu.europa.ec.dgc.gateway.restapi.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import eu.europa.ec.dgc.did.DidResolver;
import eu.europa.ec.dgc.did.DidVerificationService;
import eu.europa.ec.dgc.did.model.DidDocument;
import eu.europa.ec.dgc.did.model.VerificationMethod;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.config.OpenApiConfig;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.restapi.dto.did.TrustedDidPublicKeyDto;
import eu.europa.ec.dgc.gateway.restapi.dto.did.TrustedUploadDidDocumentDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationFilter;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
import eu.europa.ec.dgc.gateway.service.AuditService;
import eu.europa.ec.dgc.gateway.service.SignerInformationService;
import eu.europa.ec.dgc.gateway.utils.DidResolutionUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/trusted-did")
@Slf4j
@RequiredArgsConstructor
public class TrustedDidController {

    private final DidResolver didResolver;

    private final DidVerificationService didVerificationService;

    private final SignerInformationService signerInformationService;

    private final DgcConfigProperties configProperties;

    private final AuditService auditService;

    static final String AUDIT_EVENT_UPLOADED = "TRUSTED_DID_UPLOADED";
    static final String AUDIT_EVENT_NOT_VERIFIED = "TRUSTED_DID_NOT_VERIFIED";
    static final String AUDIT_EVENT_UPLOAD_FAILED = "TRUSTED_DID_UPLOAD_FAILED";
    static final String AUDIT_EVENT_DELETED = "TRUSTED_DID_DELETED";
    static final String AUDIT_EVENT_DELETE_FAILED = "TRUSTED_DID_DELETE_FAILED";

    private static final ObjectMapper VERIFY_OBJECT_MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    /**
     * Separator used by TNG to publish coded values of a verification method as DID fragment reference.
     */
    private static final String DID_FRAGMENT_SEPARATOR = "#";

    /**
     * Endpoint to upload a trusted DID document providing the coded values as path variables.
     *
     * <p>DID documents published by TNG participants do not necessarily carry the {@code domain},
     * {@code participant} and {@code keyusage} attributes within their verification methods. The path variables
     * are used as fallback for all verification methods which do not define the respective attribute. They are
     * applied with the DID fragment prefix, e.g. path variable {@code DDCC} becomes {@code "#DDCC"}.
     *
     * @param domain                      fallback domain, e.g. {@code DDCC}
     * @param participant                 fallback participant code, e.g. {@code XXA}
     * @param type                        fallback key usage, e.g. {@code CSCA}
     * @param trustedUploadDidDocumentDto the DID document to upload
     * @return a {@link ResponseEntity} with HTTP 200 containing the resolved public key on success
     */
    @CertificateAuthenticationRequired
    @PutMapping(value = "/{domain}/{participant}/{type}",
        consumes = {"application/did", "application/did+ld+json"})
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Uploads a trusted DID document with coded values provided as path variables",
        tags = {"Trusted DID", "GDHCN"},
        description = "Endpoint to upload a trusted DID document. The domain, participant and keyusage path "
            + "variables are used as fallback for verification methods which do not define these attributes. "
            + "They are applied with a leading '#', e.g. 'DDCC' becomes '#DDCC'. Every effective participant "
            + "must match the authenticated certificate's country.",
        parameters = {
            @Parameter(name = "domain", in = ParameterIn.PATH, required = true,
                description = "Fallback domain of the verification method.", example = "DDCC"),
            @Parameter(name = "participant", in = ParameterIn.PATH, required = true,
                description = "Fallback participant country code (ISO 3166 Alpha-2 or Alpha-3).",
                example = "XXA"),
            @Parameter(name = "type", in = ParameterIn.PATH, required = true,
                description = "Fallback key usage of the verification method.", example = "CSCA")
        },
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            description = "The DID document to upload.",
            content = {
                @Content(
                    mediaType = "application/did",
                    schema = @Schema(implementation = TrustedUploadDidDocumentDto.class)),
                @Content(
                    mediaType = "application/did+ld+json",
                    schema = @Schema(implementation = TrustedUploadDidDocumentDto.class))
            }
        ),
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Trusted DID document has been stored. Existing entries with the same certificate "
                    + "thumbprint are replaced.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = TrustedDidPublicKeyDto.class))),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. The submitted DID document is malformed or failed validation "
                    + "(e.g. missing/invalid attributes, invalid id/controller format, invalid public key).",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "401",
                description = "Unauthorized. No Access to the system. (Client Certificate not present or whitelisted)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "403",
                description = "Forbidden. A participant does not match the authenticated certificate's country.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "404",
                description = "Not Found. The DID could not be resolved.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "415",
                description = "Unsupported Media Type. Content-Type must be application/did "
                    + "or application/did+ld+json.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "500",
                description = "Internal Server Error. An unexpected error occurred while processing the request.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)))
        }
    )
    public ResponseEntity<TrustedDidPublicKeyDto> uploadTrustedDid(
            @PathVariable("domain") String domain,
            @PathVariable("participant") String participant,
            @PathVariable("type") String type,
            @Valid @RequestBody TrustedUploadDidDocumentDto trustedUploadDidDocumentDto,
            @RequestAttribute(value = CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY)
            String authenticatedCountry,
            @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT)
            String authThumbprint) {

        return auditedUpload(trustedUploadDidDocumentDto, domain, participant, type, authenticatedCountry,
                authThumbprint);
    }

    /**
     * Endpoint to delete the trusted DID certificates for the given domain, country and key usage.
     *
     * <p>The request body must contain a DID document whose proof is verified (same as for uploads) before
     * any certificate is deleted. Only the certificates contained in the {@code x5c} properties of the document's
     * verification methods are deleted (partial deletion); all other certificates are kept.
     *
     * @param domain                      domain of the DID document, e.g. {@code DCC}
     * @param country                     participant country code (ISO 3166 Alpha-2 or Alpha-3), e.g. {@code DE}
     * @param type                        key usage of the DID document, e.g. {@code DSC} or {@code CSCA}
     * @param trustedUploadDidDocumentDto the signed DID document authorizing the deletion
     * @return a {@link ResponseEntity} with HTTP 204 on success
     */
    @CertificateAuthenticationRequired
    @DeleteMapping(value = "/{domain}/{country}/{type}",
        consumes = {"application/did", "application/did+ld+json"})
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Deletes the trusted DID certificates listed in a DID document for a domain, country and key usage",
        tags = {"Trusted DID", "GDHCN"},
        description = "Endpoint to delete the certificates imported from uploaded trusted DID documents which are "
            + "contained in the x5c properties of the submitted document's verification methods and whose "
            + "verification method matches the given domain, country and key usage (partial deletion). Path "
            + "variables may be provided with or without leading '#'. The country must match the authenticated "
            + "certificate's country. The request body must contain a DID document with a valid proof; nothing is "
            + "deleted if the proof cannot be verified.",
        parameters = {
            @Parameter(name = "domain", in = ParameterIn.PATH, required = true,
                description = "Domain of the DID document.", example = "DCC"),
            @Parameter(name = "country", in = ParameterIn.PATH, required = true,
                description = "Participant country code (ISO 3166 Alpha-2 or Alpha-3).", example = "DEU"),
            @Parameter(name = "type", in = ParameterIn.PATH, required = true,
                description = "Key usage of the verification method.", example = "DSC")
        },
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            description = "The signed DID document authorizing the deletion.",
            content = {
                @Content(
                    mediaType = "application/did",
                    schema = @Schema(implementation = TrustedUploadDidDocumentDto.class)),
                @Content(
                    mediaType = "application/did+ld+json",
                    schema = @Schema(implementation = TrustedUploadDidDocumentDto.class))
            }
        ),
        responses = {
            @ApiResponse(
                responseCode = "204",
                description = "Trusted DID certificates have been deleted."),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. The given country code is invalid, the DID document is malformed "
                    + "or its proof could not be verified.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "401",
                description = "Unauthorized. No Access to the system. (Client Certificate not present or whitelisted)",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "403",
                description = "Forbidden. The country does not match the authenticated certificate's country.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "404",
                description = "Not Found. The DID could not be resolved or no trusted DID certificates exist for "
                    + "the given criteria.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "415",
                description = "Unsupported Media Type. Content-Type must be application/did "
                    + "or application/did+ld+json.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class))),
            @ApiResponse(
                responseCode = "500",
                description = "Internal Server Error. An unexpected error occurred while processing the request.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)))
        }
    )
    public ResponseEntity<Void> deleteTrustedDid(
            @PathVariable("domain") String domain,
            @PathVariable("country") String country,
            @PathVariable("type") String type,
            @Valid @RequestBody TrustedUploadDidDocumentDto trustedUploadDidDocumentDto,
            @RequestAttribute(value = CertificateAuthenticationFilter.REQUEST_PROP_COUNTRY)
            String authenticatedCountry,
            @RequestAttribute(CertificateAuthenticationFilter.REQUEST_PROP_THUMBPRINT)
            String authThumbprint) {

        int deletedCertificates;
        try {
            deletedCertificates = processDelete(trustedUploadDidDocumentDto, domain, country, type,
                    authenticatedCountry);
        } catch (RuntimeException e) {
            addAuditEvent(authenticatedCountry, authThumbprint, AUDIT_EVENT_DELETE_FAILED,
                    "deleteTrustedDid failed with HTTP " + statusOf(e));
            throw e;
        }

        addAuditEvent(authenticatedCountry, authThumbprint, AUDIT_EVENT_DELETED,
                String.format("deleteTrustedDid deleted %d certificate(s)", deletedCertificates));

        return ResponseEntity.noContent().build();
    }

    private int processDelete(TrustedUploadDidDocumentDto trustedUploadDidDocumentDto, String domain,
                              String country, String type, String authenticatedCountry) {
        requireAuthenticatedCountry(authenticatedCountry);
        String criteria = String.format("domain=%s, country=%s, type=%s", domain, country, type);
        log.info("Requested deletion of trusted DID certificates ({})", criteria);

        try {
            requireCountryOwnership(country, authenticatedCountry);
        } catch (SignerInformationService.SignerCertCheckException e) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x305", "Invalid Country Code",
                    criteria, e.getMessage());
        }

        requireVerifiedProof(trustedUploadDidDocumentDto);

        int deletedCertificates;
        try {
            deletedCertificates = signerInformationService.deleteDidSignerCertificates(domain, country, type,
                    trustedUploadDidDocumentDto);
        } catch (SignerInformationService.SignerCertCheckException e) {
            if (e.getReason()
                    == SignerInformationService.SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED) {
                throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x305", "Invalid Country Code",
                        criteria, e.getMessage());
            }
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x301", "DID Document Error",
                    criteria, e.getMessage());
        }

        if (deletedCertificates == 0) {
            throw new DgcgResponseException(HttpStatus.NOT_FOUND, "0x305", "DID Document Not Found", criteria,
                    "No trusted DID certificates of the submitted x5c entries found for the given domain, "
                        + "country and type.");
        }

        log.info("Deleted {} trusted DID certificate(s) ({})", deletedCertificates, criteria);

        return deletedCertificates;
    }

    /**
     * Resolves the proof's verification method and rejects the request unless the proof of the given DID
     * document is valid.
     */
    private void requireVerifiedProof(TrustedUploadDidDocumentDto trustedUploadDidDocumentDto) {
        String verificationMethodId = trustedUploadDidDocumentDto.getProof().getVerificationMethod();
        DidDocument didDocument = DidResolutionUtils.resolveOrThrow(didResolver, verificationMethodId);
        PublicKey publicKey = toPublicKey(extractJwk(didDocument, verificationMethodId), verificationMethodId);

        if (!verifyProof(trustedUploadDidDocumentDto, publicKey, verificationMethodId)) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x307", "DID Proof Verification Failed",
                    verificationMethodId, "The proof of the submitted DID document could not be verified.");
        }
    }

    private ResponseEntity<TrustedDidPublicKeyDto> auditedUpload(
            TrustedUploadDidDocumentDto trustedUploadDidDocumentDto,
            String domain,
            String participant,
            String keyusage,
            String authenticatedCountry,
            String authThumbprint) {

        ResponseEntity<TrustedDidPublicKeyDto> response;
        try {
            response = processUpload(trustedUploadDidDocumentDto, domain, participant, keyusage,
                    authenticatedCountry);
        } catch (RuntimeException e) {
            addAuditEvent(authenticatedCountry, authThumbprint, AUDIT_EVENT_UPLOAD_FAILED,
                    "uploadTrustedDid failed with HTTP " + statusOf(e));
            throw e;
        }

        TrustedDidPublicKeyDto body = response.getBody();
        if (body != null && body.isVerified()) {
            addAuditEvent(authenticatedCountry, authThumbprint, AUDIT_EVENT_UPLOADED,
                    String.format("uploadTrustedDid stored %d certificate(s)", body.getStoredCertificates()));
        } else {
            addAuditEvent(authenticatedCountry, authThumbprint, AUDIT_EVENT_NOT_VERIFIED,
                    "uploadTrustedDid proof not verified, nothing stored");
        }
        return response;
    }

    /**
     * Persists an audit event for a trusted DID operation.
     *
     * <p>Only the authenticated country, the authentication certificate thumbprint, a fixed event id and a
     * fixed description (optionally containing counters or HTTP status codes) are recorded. Request content such
     * as DID documents, DIDs, verification method ids, keys, certificates or path variables is never persisted.
     * As no separate uploader certificate exists for DID uploads, the authentication thumbprint is used as
     * uploader fingerprint.
     */
    private void addAuditEvent(String authenticatedCountry, String authThumbprint, String event,
                               String description) {
        try {
            auditService.addAuditEvent(authenticatedCountry, authThumbprint, authThumbprint, event, description);
        } catch (RuntimeException e) {
            log.error("Failed to persist trusted DID audit event {}: {}", event, e.getClass().getSimpleName());
        }
    }

    private static int statusOf(RuntimeException e) {
        return e instanceof DgcgResponseException dgcgResponseException
                ? dgcgResponseException.getStatus().value()
                : HttpStatus.INTERNAL_SERVER_ERROR.value();
    }

    private ResponseEntity<TrustedDidPublicKeyDto> processUpload(
            TrustedUploadDidDocumentDto trustedUploadDidDocumentDto,
            String domain,
            String participant,
            String keyusage,
            String authenticatedCountry) {

        requireAuthenticatedCountry(authenticatedCountry);
        String verificationMethodId = trustedUploadDidDocumentDto.getProof().getVerificationMethod();
        log.info("Received trusted DID: {} with proof verification method {}",
                trustedUploadDidDocumentDto, verificationMethodId);


        DidDocument didDocument = DidResolutionUtils.resolveOrThrow(didResolver, verificationMethodId);

        log.info("Resolved DID document for verification method {}: {}", verificationMethodId, didDocument);

        JWK jwk = extractJwk(didDocument, verificationMethodId);
        PublicKey publicKey = toPublicKey(jwk, verificationMethodId);

        log.info("Extracted public key ({}) for verification method {}",
                publicKey.getAlgorithm(), verificationMethodId);

        boolean verified = verifyProof(trustedUploadDidDocumentDto, publicKey, verificationMethodId);

        int storedCertificates = 0;

        if (verified) {
            /*
              The proof is calculated over the uploaded document, therefore the fallback values must not be
              applied before the proof has been verified.
             */
            applyCodedValueFallbacks(trustedUploadDidDocumentDto, domain, participant, keyusage);
            try {
                for (TrustedUploadDidDocumentDto.VerificationMethod verificationMethod :
                        trustedUploadDidDocumentDto.getVerificationMethod()) {
                    requireCountryOwnership(verificationMethod.getParticipant() == null
                            ? null : verificationMethod.getParticipant().getCode(), authenticatedCountry);
                }
            } catch (SignerInformationService.SignerCertCheckException e) {
                throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x303", "Invalid Country Code",
                        verificationMethodId, e.getMessage());
            }
            storedCertificates = storeUploadedDidDocument(trustedUploadDidDocumentDto, verificationMethodId);
        }

        boolean stored = storedCertificates > 0;

        TrustedDidPublicKeyDto response = new TrustedDidPublicKeyDto(
                Base64.getEncoder().encodeToString(publicKey.getEncoded()),
                verified,
                stored,
                storedCertificates,
                buildMessage(verified, storedCertificates));

        return ResponseEntity.ok(response);
    }

    /**
     * Requires the authentication filter's country unless ownership enforcement is explicitly disabled.
     */
    private void requireAuthenticatedCountry(String authenticatedCountry) {
        if (!configProperties.getTrustedDid().isEnforceCountryOwnership()) {
            log.warn("Trusted DID country ownership enforcement is disabled; use only for local development.");
        } else if (authenticatedCountry == null || authenticatedCountry.isBlank()) {
            log.warn("Trusted DID modification rejected: authenticated country is missing.");
            throw new DgcgResponseException(HttpStatus.UNAUTHORIZED, "0x400",
                    "No authentication information available", "",
                    "An authenticated country is required to modify trusted DID data.");
        }
    }

    /**
     * Rejects attempts to modify a participant other than the authenticated certificate's country.
     */
    private void requireCountryOwnership(String participant, String authenticatedCountry)
            throws SignerInformationService.SignerCertCheckException {
        if (!configProperties.getTrustedDid().isEnforceCountryOwnership()) {
            return;
        }
        String participantCountry = signerInformationService.normalizeParticipantCountryCode(participant);
        String callerCountry = signerInformationService.normalizeParticipantCountryCode(authenticatedCountry);
        if (!callerCountry.equals(participantCountry)) {
            log.warn("Country {} attempted to modify trusted DID data for country {}",
                    callerCountry, participantCountry);
            throw new DgcgResponseException(HttpStatus.FORBIDDEN, "0x306", "Invalid Country",
                    participant, "The participant must match the authenticated certificate's country.");
        }
    }

    /**
     * Builds the response message reflecting both the proof verification and the storage outcome.
     *
     * <p>The storage outcome is reported independently of the verification result, so a successful upload is
     * always visible in the response even when the proof could not be verified.
     *
     * @param verified           the result of the proof verification
     * @param storedCertificates the number of certificates which have been stored as signer information
     * @return the response message
     */
    private String buildMessage(boolean verified, int storedCertificates) {

        String verificationPart = verified ? "verified" : "not verified";

        if (storedCertificates > 0) {
            return String.format("%s, stored %d certificate(s)", verificationPart, storedCertificates);
        }

        return verificationPart + ", no certificates stored";
    }

    /**
     * Applies the coded values provided as path variables to all verification methods not defining them.
     *
     * <p>Existing values of the uploaded document are never overwritten.
     *
     * @param trustedUploadDidDocumentDto the uploaded DID document to enrich
     * @param domain                      fallback domain, may be {@code null}
     * @param participant                 fallback participant code, may be {@code null}
     * @param keyusage                    fallback key usage, may be {@code null}
     */
    private void applyCodedValueFallbacks(TrustedUploadDidDocumentDto trustedUploadDidDocumentDto,
                                          String domain,
                                          String participant,
                                          String keyusage) {

        if (trustedUploadDidDocumentDto.getVerificationMethod() == null) {
            return;
        }

        for (TrustedUploadDidDocumentDto.VerificationMethod verificationMethod :
                trustedUploadDidDocumentDto.getVerificationMethod()) {

            if (isBlank(verificationMethod.getDomain())) {
                verificationMethod.setDomain(toCodeWrapper(domain));
            }

            if (isBlank(verificationMethod.getParticipant())) {
                verificationMethod.setParticipant(toCodeWrapper(participant));
            }

            if (isBlank(verificationMethod.getKeyUsage())) {
                verificationMethod.setKeyUsage(toCodeWrapper(keyusage));
            }
        }
    }

    private boolean isBlank(TrustedUploadDidDocumentDto.CodeWrapper codeWrapper) {
        return codeWrapper == null || codeWrapper.getCode() == null || codeWrapper.getCode().isBlank();
    }

    /**
     * Wraps a path variable as coded value using the DID fragment prefix, e.g. {@code DDCC} becomes {@code #DDCC}.
     *
     * @param value the path variable value, may be {@code null}
     * @return the wrapped coded value or {@code null} if no value was provided
     */
    private TrustedUploadDidDocumentDto.CodeWrapper toCodeWrapper(String value) {

        if (value == null || value.isBlank()) {
            return null;
        }

        String code = value.trim();
        if (!code.startsWith(DID_FRAGMENT_SEPARATOR)) {
            code = DID_FRAGMENT_SEPARATOR + code;
        }

        TrustedUploadDidDocumentDto.CodeWrapper codeWrapper = new TrustedUploadDidDocumentDto.CodeWrapper();
        codeWrapper.setCode(code);

        return codeWrapper;
    }

    /**
     * Verifies the signature proof of the uploaded DID document.
     *
     * @param trustedUploadDidDocumentDto the uploaded signed DID document to verify
     * @param publicKey                   the resolved public key used for verification
     * @param verificationMethodId        the id of the verification method (used for error reporting)
     * @return {@code true} if the verifier reports the proof as valid, {@code false} otherwise
     */
    private boolean verifyProof(TrustedUploadDidDocumentDto trustedUploadDidDocumentDto,
                                PublicKey publicKey,
                                String verificationMethodId) {
        try {
            String didDocument = VERIFY_OBJECT_MAPPER.writeValueAsString(trustedUploadDidDocumentDto);
            boolean verificationResult = didVerificationService.verify(didDocument, publicKey);
            log.info("Proof verification result for verification method {}: {}",
                    verificationMethodId, verificationResult);
            return verificationResult;
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize DID document for proof verification for verification method {}: {}",
                    verificationMethodId, e.getMessage());
            throw new DgcgResponseException(HttpStatus.BAD_GATEWAY, "0x302", "DID Proof Verification Error",
                    verificationMethodId, "Failed to verify proof of the uploaded DID document.");
        }
    }

    /**
     * Stores the certificates of a successfully verified DID document as signer information.
     *
     * @param trustedUploadDidDocumentDto the verified DID document to store
     * @param verificationMethodId        the id of the verification method (used for error reporting)
     * @return the number of certificates which have been stored as signer information
     */
    private int storeUploadedDidDocument(TrustedUploadDidDocumentDto trustedUploadDidDocumentDto,
                                         String verificationMethodId) {
        try {
            List<SignerInformationEntity> storedEntities =
                    signerInformationService.addDidSignerCertificates(trustedUploadDidDocumentDto);

            log.info("Stored {} SignerInformation entries from uploaded DID document for verification method {}",
                    storedEntities.size(), verificationMethodId);

            return storedEntities.size();
        } catch (SignerInformationService.SignerCertCheckException e) {
            log.error("Failed to store uploaded DID document for verification method {}: {}",
                    verificationMethodId, e.getMessage());
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x303", "DID Upload Storage Error",
                    verificationMethodId, e.getMessage());
        }
    }

    /**
     * Extracts the {@link JWK} of the verification method matching the given id from a resolved DID document.
     *
     * <p>The JWK is parsed from the verification method's {@code publicKeyJwk} raw key material
     * ({@code kty}/{@code crv}/{@code x}/{@code y} for EC, {@code n}/{@code e} for RSA).
     *
     * @param didDocument          the resolved DID document
     * @param verificationMethodId the id of the verification method to extract the JWK from
     * @return the extracted JWK
     */
    private JWK extractJwk(DidDocument didDocument, String verificationMethodId) {
        List<VerificationMethod> verificationMethods =
                didDocument != null ? didDocument.getVerificationMethod() : null;

        if (verificationMethods == null || verificationMethods.isEmpty()) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x301", "DID Document Error",
                    verificationMethodId, "Resolved DID document does not contain any verification method.");
        }

        VerificationMethod verificationMethod = verificationMethods.stream()
                .filter(vm -> verificationMethodId.equals(vm.getId()))
                .findFirst()
                .orElseThrow(() -> new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x301", "DID Document Error",
                        verificationMethodId, "Verification method not found in resolved DID document."));

        Map<String, Object> publicKeyJwk = verificationMethod.getPublicKeyJwk();
        if (publicKeyJwk == null || publicKeyJwk.isEmpty()) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x301", "DID Document Error",
                    verificationMethodId, "Verification method does not contain a publicKeyJwk.");
        }

        try {
            return JWK.parse(publicKeyJwk);
        } catch (ParseException e) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x301", "DID Document Error",
                    verificationMethodId, "Failed to parse publicKeyJwk of verification method: " + e.getMessage());
        }
    }

    /**
     * Converts a parsed {@link JWK} into a {@link PublicKey}.
     *
     * @param jwk                  the JWK to convert
     * @param verificationMethodId the id of the verification method the JWK belongs to
     * @return the extracted public key
     */
    private PublicKey toPublicKey(JWK jwk, String verificationMethodId) {
        try {
            if (jwk instanceof AsymmetricJWK asymmetricJwk) {
                return asymmetricJwk.toPublicKey();
            }

            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x301", "DID Document Error",
                    verificationMethodId, "Unsupported public key type in publicKeyJwk.");
        } catch (JOSEException e) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x301", "DID Document Error",
                    verificationMethodId, "Failed to extract public key from verification method: " + e.getMessage());
        }
    }
}
