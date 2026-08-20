package eu.europa.ec.dgc.gateway.restapi.dto.did;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

@Data
@JsonPropertyOrder({"@context", "id", "verificationMethod", "proof"})
public class TrustedUploadDidDocumentDto {

    @NotEmpty
    @JsonProperty("@context")
    private List<@NotBlank String> context;

    @NotBlank
    @Pattern(regexp = "^did:[a-z0-9]+:.+")
    private String id;

    @NotBlank
    @Pattern(regexp = "^did:[a-z0-9]+:.+")
    private String controller;

    @NotEmpty
    @Valid
    private List<VerificationMethod> verificationMethod;

    @NotNull
    @Valid
    private Proof proof;


    @NoArgsConstructor
    @Getter
    @Setter
    public static class VerificationMethod {
        @NotBlank
        @Pattern(regexp = "^did:[a-z0-9]+:.+")
        private String id;

        @NotBlank
        private String type;

        @NotBlank
        @Pattern(regexp = "^did:[a-z0-9]+:.+")
        private String controller;

        @NotNull
        @Valid
        private PublicKeyJwk publicKeyJwk;

        @Valid
        private CodeWrapper domain;

        @Valid
        private CodeWrapper participant;

        @JsonProperty("keyusage")
        @Valid
        private CodeWrapper keyUsage;
    }

    @NoArgsConstructor
    @Getter
    @Setter
    public static class CodeWrapper {
        @NotBlank
        private String code;
    }

    @NoArgsConstructor
    @Setter
    @Getter
    @JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        include = JsonTypeInfo.As.EXISTING_PROPERTY,
        property = "kty",
        visible = true)
    @JsonSubTypes({
        @JsonSubTypes.Type(value = EcPublicKeyJwk.class, name = "EC"),
        @JsonSubTypes.Type(value = RsaPublicKeyJwk.class, name = "RSA")
    })
    public abstract static class PublicKeyJwk {
        @NotBlank
        @JsonProperty("kty")
        private String keyType;

        @NotEmpty
        @JsonProperty("x5c")
        private List<@NotBlank String> encodedX509Certificates;

        private PublicKeyJwk(String keyType, List<String> encodedX509Certificates) {
            this.keyType = keyType;
            this.encodedX509Certificates = new ArrayList<>(encodedX509Certificates);
        }
    }

    @Getter
    @Setter
    @NoArgsConstructor
    public static class EcPublicKeyJwk extends PublicKeyJwk {

        @NotBlank
        @JsonProperty("crv")
        private String curve;

        @NotBlank
        @JsonProperty("x")
        private String valueX;

        @NotBlank
        @JsonProperty("y")
        private String valueY;

        /**
         * Instantiate EC PublicKey JWK Class.
         *
         * @param ecPublicKey               EC Public Key that should be wrapped.
         * @param base64EncodedCertificates List of Base64 encoded Certificates assigned to provided Public Key.
         *                                  They will be added within x5c property of JWK.
         */
        public EcPublicKeyJwk(ECPublicKey ecPublicKey, List<String> base64EncodedCertificates) {
            super("EC", base64EncodedCertificates);
            valueX = Base64.getUrlEncoder().encodeToString(ecPublicKey.getW().getAffineX().toByteArray());
            valueY = Base64.getUrlEncoder().encodeToString(ecPublicKey.getW().getAffineY().toByteArray());

            ECNamedCurveSpec curveSpec = (ECNamedCurveSpec) ecPublicKey.getParams();
            switch (curveSpec.getName()) {
                case "prime256v1" -> curve = "P-256";
                case "prime384v1" -> curve = "P-384";
                case "prime521v1" -> curve = "P-521";
                default -> curve = "UNKNOWN CURVE";
            }
        }
    }

    @Getter
    @Setter
    @NoArgsConstructor
    public static class RsaPublicKeyJwk extends PublicKeyJwk {

        @NotBlank
        @JsonProperty("e")
        private String valueE;

        @NotBlank
        @JsonProperty("n")
        private String valueN;

        /**
         * Instantiate RSA PublicKey JWK Class.
         *
         * @param rsaPublicKey              RSA Public Key that should be wrapped.
         * @param base64EncodedCertificates List of Base64 encoded Certificates assigned to provided Public Key.
         *                                  They will be added within x5c property of JWK.
         */
        public RsaPublicKeyJwk(RSAPublicKey rsaPublicKey, List<String> base64EncodedCertificates) {
            super("RSA", base64EncodedCertificates);
            valueN = Base64.getUrlEncoder().encodeToString(rsaPublicKey.getModulus().toByteArray());
            valueE = Base64.getUrlEncoder().encodeToString(rsaPublicKey.getPublicExponent().toByteArray());
        }
    }

    @Getter
    @Setter
    public static class Proof {
        @NotBlank
        private String type;

        @NotBlank
        private String created;

        @NotBlank
        private String proofPurpose;

        @NotBlank
        private String verificationMethod;

        @NotBlank
        private String jws;

        /**
         * Instantiate the proof class.
         *
         * @param type The type of the proof
         * @param created The creation date of the proof
         * @param proofPurpose The purpose of the proof
         * @param verificationMethod The method used for verification
         * @param jws The JSON Web Signature
         */
        public Proof(String type, String created, String proofPurpose, String verificationMethod, String jws) {
            this.type = type;
            this.created = created;
            this.proofPurpose = proofPurpose;
            this.verificationMethod = verificationMethod;
            this.jws = jws;
        }
    }

}
