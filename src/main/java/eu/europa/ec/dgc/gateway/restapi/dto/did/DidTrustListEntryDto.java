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

package eu.europa.ec.dgc.gateway.restapi.dto.did;

import com.fasterxml.jackson.annotation.JsonProperty;
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
public class DidTrustListEntryDto {

    private String id;

    private String type;

    private String controller;

    private PublicKeyJwk publicKeyJwk;

    @NoArgsConstructor
    @Setter
    @Getter
    public abstract static class PublicKeyJwk {
        @JsonProperty("kty")
        private String keyType;

        @JsonProperty("x5c")
        private List<String> encodedX509Certificates;

        @JsonProperty("kid")
        private String keyId;

        private PublicKeyJwk(String keyType, List<String> encodedX509Certificates, String keyId) {
            this.keyType = keyType;
            this.encodedX509Certificates = new ArrayList<>(encodedX509Certificates);
            this.keyId = keyId;
        }
    }

    @Getter
    @Setter
    public static class EcPublicKeyJwk extends PublicKeyJwk {

        @JsonProperty("crv")
        private String curve;

        @JsonProperty("x")
        private String valueX;

        @JsonProperty("y")
        private String valueY;

        /**
         * Instantiate EC PublicKey JWK Class.
         *
         * @param ecPublicKey EC Public Key that should be wrapped.
         * @param base64EncodedCertificates List of Base64 encoded Certificates assigned to provided Public Key.
         *                                   They will be added within x5c property of JWK.
         */
        public EcPublicKeyJwk(ECPublicKey ecPublicKey, List<String> base64EncodedCertificates, String keyId) {
            super("EC", base64EncodedCertificates, keyId);
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
    public static class RsaPublicKeyJwk extends PublicKeyJwk {

        @JsonProperty("e")
        private String valueE;

        @JsonProperty("n")
        private String valueN;

        /**
         * Instantiate RSA PublicKey JWK Class.
         *
         * @param rsaPublicKey              RSA Public Key that should be wrapped.
         * @param base64EncodedCertificates List of Base64 encoded Certificates assigned to provided Public Key.
         *                                  They will be added within x5c property of JWK.
         */
        public RsaPublicKeyJwk(RSAPublicKey rsaPublicKey, List<String> base64EncodedCertificates, String keyId) {
            super("RSA", base64EncodedCertificates, keyId);
            valueN = Base64.getUrlEncoder().encodeToString(rsaPublicKey.getModulus().toByteArray());
            valueE = Base64.getUrlEncoder().encodeToString(rsaPublicKey.getPublicExponent().toByteArray());
        }
    }

}
