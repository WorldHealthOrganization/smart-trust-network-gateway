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
