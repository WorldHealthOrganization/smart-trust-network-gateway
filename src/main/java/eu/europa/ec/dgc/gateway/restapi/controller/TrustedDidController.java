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
import eu.europa.ec.dgc.gateway.config.OpenApiConfig;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.restapi.dto.did.TrustedDidPublicKeyDto;
import eu.europa.ec.dgc.gateway.restapi.dto.did.TrustedUploadDidDocumentDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
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

    private static final ObjectMapper VERIFY_OBJECT_MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    /**
     * Separator used by TNG to publish coded values of a verification method as DID fragment reference.
     */
    private static final String DID_FRAGMENT_SEPARATOR = "#";

    private static final String CONTENT_TYPE_DID_LD_JSON = "application/did+ld+json";

    /**
     * Endpoint to upload a trusted DID document.
     *
     * @param trustedUploadDidDocumentDto the DID document to upload
     * @return a {@link ResponseEntity} with HTTP 200 containing the resolved public key on success
     */
    @CertificateAuthenticationRequired
    @PutMapping(consumes = {"application/did", "application/did+ld+json"})
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Uploads a trusted DID document",
        tags = {"Trusted DID", "GDHCN"},
        description = "Endpoint to upload a trusted DID document. Certificates already stored from a DID "
            + "document are replaced; certificates stored via CMS are removed and re-created as DID entries.",
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
            @Valid @RequestBody TrustedUploadDidDocumentDto trustedUploadDidDocumentDto) {

        return processUpload(trustedUploadDidDocumentDto, null, null, null);
    }

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
     * @param keyusage                    fallback key usage, e.g. {@code CSCA}
     * @param trustedUploadDidDocumentDto the DID document to upload
     * @return a {@link ResponseEntity} with HTTP 200 containing the resolved public key on success
     */
    @CertificateAuthenticationRequired
    @PutMapping(value = "/{domain}/{participant}/{keyusage}",
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
            + "They are applied with a leading '#', e.g. 'DDCC' becomes '#DDCC'.",
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
            @PathVariable("keyusage") String keyusage,
            @Valid @RequestBody TrustedUploadDidDocumentDto trustedUploadDidDocumentDto) {

        return processUpload(trustedUploadDidDocumentDto, domain, participant, keyusage);
    }

    /**
     * Endpoint to download the uploaded trusted DID document for the given domain, country and key usage.
     *
     * @param domain  domain of the DID document, e.g. {@code DCC}
     * @param country participant country code (ISO 3166 Alpha-2 or Alpha-3), e.g. {@code DE} or {@code DEU}
     * @param type    key usage of the DID document, e.g. {@code DSC} or {@code CSCA}
     * @return a {@link ResponseEntity} with HTTP 200 containing the stored DID document
     */
    @CertificateAuthenticationRequired
    @GetMapping(value = "/{domain}/{country}/{type}",
        produces = {CONTENT_TYPE_DID_LD_JSON, MediaType.APPLICATION_JSON_VALUE})
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Returns the trusted DID document for a domain, country and key usage",
        tags = {"Trusted DID", "GDHCN"},
        description = "Endpoint to download the latest uploaded trusted DID document containing a verification "
            + "method matching the given domain, country and key usage. Path variables may be provided with or "
            + "without leading '#'.",
        parameters = {
            @Parameter(name = "domain", in = ParameterIn.PATH, required = true,
                description = "Domain of the DID document.", example = "DCC"),
            @Parameter(name = "country", in = ParameterIn.PATH, required = true,
                description = "Participant country code (ISO 3166 Alpha-2 or Alpha-3).", example = "DEU"),
            @Parameter(name = "type", in = ParameterIn.PATH, required = true,
                description = "Key usage of the verification method.", example = "DSC")
        },
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Trusted DID document has been found.",
                content = @Content(
                    mediaType = CONTENT_TYPE_DID_LD_JSON,
                    schema = @Schema(implementation = TrustedUploadDidDocumentDto.class))),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. The given country code is invalid.",
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
                responseCode = "404",
                description = "Not Found. No trusted DID document exists for the given criteria.",
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
    public ResponseEntity<String> getTrustedDid(
            @PathVariable("domain") String domain,
            @PathVariable("country") String country,
            @PathVariable("type") String type) {

        String criteria = String.format("domain=%s, country=%s, type=%s", domain, country, type);
        log.info("Requested trusted DID document ({})", criteria);

        try {
            String didDocument = signerInformationService.getDidDocument(domain, country, type)
                    .orElseThrow(() -> new DgcgResponseException(HttpStatus.NOT_FOUND, "0x304",
                            "DID Document Not Found", criteria,
                            "No trusted DID document found for the given domain, country and type."));

            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType(CONTENT_TYPE_DID_LD_JSON))
                    .body(didDocument);
        } catch (SignerInformationService.SignerCertCheckException e) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x304", "Invalid Country Code",
                    criteria, e.getMessage());
        }
    }

    /**
     * Endpoint to delete the trusted DID certificates for the given domain, country and key usage.
     *
     * @param domain  domain of the DID document, e.g. {@code DCC}
     * @param country participant country code (ISO 3166 Alpha-2 or Alpha-3), e.g. {@code DE} or {@code DEU}
     * @param type    key usage of the DID document, e.g. {@code DSC} or {@code CSCA}
     * @return a {@link ResponseEntity} with HTTP 204 on success
     */
    @CertificateAuthenticationRequired
    @DeleteMapping(value = "/{domain}/{country}/{type}")
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        summary = "Deletes the trusted DID certificates for a domain, country and key usage",
        tags = {"Trusted DID", "GDHCN"},
        description = "Endpoint to delete all certificates imported from uploaded trusted DID documents whose "
            + "verification method matches the given domain, country and key usage. Path variables may be "
            + "provided with or without leading '#'.",
        parameters = {
            @Parameter(name = "domain", in = ParameterIn.PATH, required = true,
                description = "Domain of the DID document.", example = "DCC"),
            @Parameter(name = "country", in = ParameterIn.PATH, required = true,
                description = "Participant country code (ISO 3166 Alpha-2 or Alpha-3).", example = "DEU"),
            @Parameter(name = "type", in = ParameterIn.PATH, required = true,
                description = "Key usage of the verification method.", example = "DSC")
        },
        responses = {
            @ApiResponse(
                responseCode = "204",
                description = "Trusted DID certificates have been deleted."),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. The given country code is invalid.",
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
                responseCode = "404",
                description = "Not Found. No trusted DID certificates exist for the given criteria.",
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
            @PathVariable("type") String type) {

        String criteria = String.format("domain=%s, country=%s, type=%s", domain, country, type);
        log.info("Requested deletion of trusted DID certificates ({})", criteria);

        int deletedCertificates;
        try {
            deletedCertificates = signerInformationService.deleteDidSignerCertificates(domain, country, type);
        } catch (SignerInformationService.SignerCertCheckException e) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "0x305", "Invalid Country Code",
                    criteria, e.getMessage());
        }

        if (deletedCertificates == 0) {
            throw new DgcgResponseException(HttpStatus.NOT_FOUND, "0x305", "DID Document Not Found", criteria,
                    "No trusted DID certificates found for the given domain, country and type.");
        }

        log.info("Deleted {} trusted DID certificate(s) ({})", deletedCertificates, criteria);

        return ResponseEntity.noContent().build();
    }

    private ResponseEntity<TrustedDidPublicKeyDto> processUpload(
            TrustedUploadDidDocumentDto trustedUploadDidDocumentDto,
            String domain,
            String participant,
            String keyusage) {

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

        if (true) {
            /*
              The proof is calculated over the uploaded document, therefore the fallback values must not be
              applied before the proof has been verified.
             */
            applyCodedValueFallbacks(trustedUploadDidDocumentDto, domain, participant, keyusage);
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
