/*-
 * ---license-start
 * WHO Digital Documentation Covid Certificate Gateway Service / ddcc-gateway
 * ---
 * Copyright (C) 2022 - 2023 T-Systems International GmbH and all other contributors
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

package eu.europa.ec.dgc.gateway.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class CloudmersiveThreatDetectionResponse {

    @JsonProperty("Successful")
    @NotNull
    Boolean successful;

    @JsonProperty("CleanResult")
    @NotNull
    Boolean cleanResult;

    @JsonProperty("ContainedJsonInsecureDeserializationAttack")
    @NotNull
    Boolean containedJsonInsecureDeserializationAttack;

    @JsonProperty("ContainedXssThreat")
    @NotNull
    Boolean containedXssThreat;

    @JsonProperty("ContainedXxeThreat")
    @NotNull
    Boolean containedXxeThreat;

    @JsonProperty("ContainedSqlInjectionThreat")
    @NotNull
    Boolean containedSqlInjectionThreat;

    @JsonProperty("ContainedSsrfThreat")
    @NotNull
    Boolean containedSsrfThreat;

    @JsonProperty("IsXML")
    @NotNull
    Boolean isXml;

    @JsonProperty("IsJSON")
    @NotNull
    Boolean isJson;

    @JsonProperty("IsURL")
    @NotNull
    Boolean isUrl;

    @JsonProperty("OriginalInput")
    String originalInput;

}
