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

package eu.europa.ec.dgc.gateway.utils;

import eu.europa.ec.dgc.did.DidResolver;
import eu.europa.ec.dgc.did.model.DidDocument;
import eu.europa.ec.dgc.did.model.DidResolutionMetadata;
import eu.europa.ec.dgc.did.model.DidResolutionResult;
import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;

/**
 * Helper for resolving DIDs and translating resolution failures into HTTP responses.
 */
@Slf4j
public class DidResolutionUtils {

    private static final String ERROR_CODE_RESOLUTION = "0x300";
    private static final String ERROR_TITLE_RESOLUTION = "DID Resolution Error";
    private static final String DEFAULT_ERROR_MESSAGE = "DID resolution failed";

    private DidResolutionUtils() {
    }

    /**
     * Resolves the given DID and returns the DID document of a successful resolution.
     *
     * <p>The returned DID document may be {@code null} if the resolver reported success without
     * providing a document. Callers that require a document must handle that case themselves.
     *
     * @param didResolver the resolver used to resolve the DID
     * @param did         the DID (or DID URL) to resolve
     * @return the resolved DID document
     * @throws DgcgResponseException if the DID could not be resolved
     */
    public static DidDocument resolveOrThrow(DidResolver didResolver, String did) {

        DidResolutionResult didResolutionResult = didResolver.resolve(did);

        if (didResolutionResult.isError()) {
            DidResolutionMetadata metadata = didResolutionResult.getDidResolutionMetadata();
            String error = metadata != null && metadata.getError() != null
                    ? metadata.getError() : DidResolutionMetadata.ERROR_INTERNAL;
            String errorMessage = metadata != null && metadata.getErrorMessage() != null
                    ? metadata.getErrorMessage() : DEFAULT_ERROR_MESSAGE;

            log.warn("DID resolution failed for {}: {} - {}", did, error, errorMessage);

            throw new DgcgResponseException(getHttpStatus(error), ERROR_CODE_RESOLUTION,
                    ERROR_TITLE_RESOLUTION, did, errorMessage);
        }

        return didResolutionResult.getDidDocument();
    }

    /**
     * Maps a DID resolution error to the corresponding HTTP status.
     *
     * @param error the error reported within the DID resolution metadata
     * @return the HTTP status to respond with
     */
    public static HttpStatus getHttpStatus(String error) {
        return switch (error) {
            case DidResolutionMetadata.ERROR_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case DidResolutionMetadata.ERROR_INVALID_DID,
                 DidResolutionMetadata.ERROR_METHOD_NOT_SUPPORTED -> HttpStatus.BAD_REQUEST;
            default -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
    }
}
