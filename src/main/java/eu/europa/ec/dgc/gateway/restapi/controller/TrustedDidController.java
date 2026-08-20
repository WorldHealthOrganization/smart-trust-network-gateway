package eu.europa.ec.dgc.gateway.restapi.controller;

import eu.europa.ec.dgc.did.DidResolver;
import eu.europa.ec.dgc.did.model.DidDocument;
import eu.europa.ec.dgc.did.model.DidResolutionMetadata;
import eu.europa.ec.dgc.did.model.DidResolutionResult;
import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.restapi.dto.did.TrustedUploadDidDocumentDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
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

    /**
     * Endpoint to upload a trusted DID document.
     *
     * @param trustedUploadDidDocumentDto the DID document to upload
     * @return an empty {@link ResponseEntity} with HTTP 200 on success
     */
    @PostMapping(consumes = "application/did+ld+json")
    @Operation(
        summary = "Uploads a trusted DID document",
        tags = {"Trusted DID", "GDHCN"},
        description = "Endpoint to upload a trusted DID document.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            description = "The DID document to upload.",
            content = @Content(
                mediaType = "application/did+ld+json",
                schema = @Schema(implementation = TrustedUploadDidDocumentDto.class))
        ),
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Trusted DID document has been uploaded successfully."),
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
                description = "Unsupported Media Type. Content-Type must be application/did+ld+json.",
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
    public ResponseEntity<DidDocument> uploadTrustedDid(
        @Valid @RequestBody TrustedUploadDidDocumentDto trustedUploadDidDocumentDto) {
        log.info("Received trusted DID: {}", trustedUploadDidDocumentDto);

        String verificationMethodId = trustedUploadDidDocumentDto.getProof().getVerificationMethod();

        DidResolutionResult didResolutionResult = didResolver.resolve(verificationMethodId);

        if (didResolutionResult.isError()) {
            DidResolutionMetadata metadata = didResolutionResult.getDidResolutionMetadata();
            String error = metadata != null && metadata.getError() != null
                ? metadata.getError() : DidResolutionMetadata.ERROR_INTERNAL;
            String errorMessage = metadata != null && metadata.getErrorMessage() != null
                ? metadata.getErrorMessage() : "DID resolution failed";

            log.warn("DID resolution failed for {}: {} - {}", verificationMethodId, error, errorMessage);

            HttpStatus status = switch (error) {
                case DidResolutionMetadata.ERROR_NOT_FOUND -> HttpStatus.NOT_FOUND;
                case DidResolutionMetadata.ERROR_INVALID_DID,
                     DidResolutionMetadata.ERROR_METHOD_NOT_SUPPORTED -> HttpStatus.BAD_REQUEST;
                default -> HttpStatus.INTERNAL_SERVER_ERROR;
            };

            throw new DgcgResponseException(status, "0x300", "DID Resolution Error",
                    verificationMethodId, errorMessage);
        }

        return ResponseEntity.ok(didResolutionResult.getDidDocument());
    }
}
