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

import eu.europa.ec.dgc.gateway.config.OpenApiConfig;
import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.restapi.dto.revocation.RevocationBatchListDto;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRequired;
import eu.europa.ec.dgc.gateway.restapi.filter.CertificateAuthenticationRole;
import eu.europa.ec.dgc.gateway.restapi.mapper.RevocationBatchMapper;
import eu.europa.ec.dgc.gateway.service.RevocationListService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/revocation-list")
@RequiredArgsConstructor
@Validated
@Slf4j
@ConditionalOnProperty(name = "dgc.revocation.enabled", havingValue = "true")
public class CertificateRevocationListDefaultController {

    private final RevocationListService revocationListService;

    private final RevocationBatchMapper revocationBatchMapper;

    public static final String UUID_REGEX =
        "^[0-9a-f]{8}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{12}$";

    private static final String MDC_DOWNLOADER_COUNTRY = "downloaderCountry";
    private static final String MDC_DOWNLOADED_COUNTRY = "downloadedCountry";
    private static final String MDC_DOWNLOADED_BATCH_ID = "downloadedBatchId";

    /**
     * Endpoint to download Revocation Batch List.
     */
    @CertificateAuthenticationRequired(requiredRoles = CertificateAuthenticationRole.RevocationListReader)
    @GetMapping(path = "", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
        security = {
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_HASH),
            @SecurityRequirement(name = OpenApiConfig.SECURITY_SCHEMA_DISTINGUISH_NAME)
        },
        tags = {"Revocation"},
        summary = "Download Batch List",
        description = "Returning a list of batches with a small wrapper providing metadata."
            + " The batches are sorted by date in ascending (chronological) order.",
        parameters = {
            @Parameter(
                in = ParameterIn.HEADER,
                name = HttpHeaders.IF_MODIFIED_SINCE,
                description = "This header contains the last downloaded date to get just the latest results. "
                    + "On the initial call the header should be the set to ‘2021-06-01T00:00:00Z’",
                required = true)
        },
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Response contains the batch list.",
                content = @Content(schema = @Schema(implementation = RevocationBatchListDto.class))),
            @ApiResponse(
                responseCode = "204",
                description = "No Content if no data is available later than provided If-Modified-Since header.")
        }
    )
    public ResponseEntity<RevocationBatchListDto> downloadBatchList(
        @Valid @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
        @RequestHeader(HttpHeaders.IF_MODIFIED_SINCE) ZonedDateTime ifModifiedSince) {

        if (ifModifiedSince.isAfter(ZonedDateTime.now())) {
            throw new DgcgResponseException(HttpStatus.BAD_REQUEST, "", "IfModifiedSince must be in past", "", "");
        }

        RevocationBatchListDto revocationBatchListDto =
            revocationBatchMapper.toDto(revocationListService.getRevocationBatchList(ifModifiedSince));

        if (revocationBatchListDto.getBatches().isEmpty()) {
            return ResponseEntity.noContent().build();
        } else {
            return ResponseEntity.ok(revocationBatchListDto);
        }
    }
}
