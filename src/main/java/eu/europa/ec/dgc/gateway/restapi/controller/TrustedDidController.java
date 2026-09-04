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
import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.restapi.dto.did.TrustedDidPublicKeyDto;
import eu.europa.ec.dgc.gateway.restapi.dto.did.TrustedUploadDidDocumentDto;
import eu.europa.ec.dgc.gateway.utils.DidResolutionUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
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
import org.springframework.web.bind.annotation.PostMapping;
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

    private static final ObjectMapper VERIFY_OBJECT_MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    /**
     * Endpoint to upload a trusted DID document.
     *
     * @param trustedUploadDidDocumentDto the DID document to upload
     * @return a {@link ResponseEntity} with HTTP 200 containing the resolved public key on success
     */
    @PostMapping(consumes = {"application/did", "application/did+ld+json"})
    @Operation(
        summary = "Uploads a trusted DID document",
        tags = {"Trusted DID", "GDHCN"},
        description = "Endpoint to upload a trusted DID document.",
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
                description = "Trusted DID document has been uploaded successfully.",
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

        TrustedDidPublicKeyDto response = new TrustedDidPublicKeyDto(
                Base64.getEncoder().encodeToString(publicKey.getEncoded()),
                verified,
                verified ? "verified" : "not verified");

        return ResponseEntity.ok(response);
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
