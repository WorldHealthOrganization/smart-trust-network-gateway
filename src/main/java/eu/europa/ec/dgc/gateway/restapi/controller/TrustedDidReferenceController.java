/*-
 * ---license-start
 * WHO Digital Documentation Covid Certificate Gateway Service / ddcc-gateway
 * ---
 * Copyright (C) 2022 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package eu.europa.ec.dgc.gateway.restapi.controller;

import eu.europa.ec.dgc.did.DidResolver;
import eu.europa.ec.dgc.did.model.DidDocument;
import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.utils.DidResolutionUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/trusted-did-reference")
@Slf4j
@RequiredArgsConstructor
public class TrustedDidReferenceController {

    private static final String CONTENT_TYPE_DID_LD_JSON = "application/did+ld+json";

    private final DidResolver didResolver;

    /**
     * Endpoint to resolve a DID and return its DID document.
     *
     * @param did the DID (or DID URL) to resolve, provided as query parameter
     * @return a {@link ResponseEntity} with HTTP 200 containing the resolved DID document
     */
    @GetMapping(produces = {CONTENT_TYPE_DID_LD_JSON, MediaType.APPLICATION_JSON_VALUE})
    @Operation(
        summary = "Resolves a DID and returns the corresponding DID document",
        tags = {"Trusted DID", "GDHCN"},
        description = "Endpoint to resolve a given DID with the configured DID resolver "
            + "and return the corresponding DID document.",
        parameters = {
            @Parameter(
                name = "did",
                in = ParameterIn.QUERY,
                required = true,
                description = "The DID to resolve, e.g. did:web:example.com:did:participant.",
                example = "did:web:example.com")
        },
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "DID has been resolved successfully.",
                content = @Content(
                    mediaType = CONTENT_TYPE_DID_LD_JSON,
                    schema = @Schema(implementation = DidDocument.class))),
            @ApiResponse(
                responseCode = "400",
                description = "Bad request. The given DID is malformed or its method is not supported.",
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
                responseCode = "500",
                description = "Internal Server Error. An unexpected error occurred while processing the request.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = ProblemReportDto.class)))
        }
    )
    public ResponseEntity<DidDocument> getTrustedDidReference(@RequestParam("did") String did) {

        log.info("Resolving DID reference: {}", did);

        DidDocument didDocument = DidResolutionUtils.resolveOrThrow(didResolver, did);

        if (didDocument == null) {
            log.warn("DID resolution for {} did not return a DID document.", did);
            throw new DgcgResponseException(HttpStatus.NOT_FOUND, "0x301", "DID Document Error", did,
                    "Resolved DID does not contain a DID document.");
        }

        log.info("Resolved DID document for {}: {}", did, didDocument);

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(CONTENT_TYPE_DID_LD_JSON))
                .body(didDocument);
    }
}
