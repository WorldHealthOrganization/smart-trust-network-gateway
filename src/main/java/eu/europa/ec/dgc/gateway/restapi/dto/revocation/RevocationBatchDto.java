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

package eu.europa.ec.dgc.gateway.restapi.dto.revocation;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.ZonedDateTime;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Length;

@Schema(description = "Batch entry with list of revoked certificates.")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RevocationBatchDto {

    @Schema(description = "ISO 3166 2-Digit Country Code")
    @Length(min = 2, max = 2)
    @NotNull
    private String country;

    @Schema(description = "Date when the item can be removed")
    @NotNull
    private ZonedDateTime expires;


    @Schema(description = "Base64 encoded KID of the DSC used to sign the Batch. Use UNKNOWN_KID if kid is not known.")
    @Length(min = 11, max = 12)
    private String kid;

    @Schema(description = "Hash Type of the provided entries")
    private RevocationHashTypeDto hashType;

    @Schema(description = "List of revoked certificate hashes")
    @Size(min = 1, max = 1000)
    private List<BatchEntryDto> entries;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BatchEntryDto {

        @Schema(description = "Base64 encoded first 128 Bits of the hash of the Entry")
        @Pattern(regexp = "^[A-Za-z0-9+/]{22}==$") // Pattern for Base64 String representing exactly 16 bytes
        @Length(min = 24, max = 24)
        private String hash;

    }
}
