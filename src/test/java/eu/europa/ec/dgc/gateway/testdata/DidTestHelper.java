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

package eu.europa.ec.dgc.gateway.testdata;

import com.apicatalog.jsonld.loader.DocumentLoader;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.nimbusds.jose.JWSAlgorithm;
import eu.europa.ec.dgc.did.model.DidResolutionMetadata;
import eu.europa.ec.dgc.did.model.DidResolutionResult;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.signer.JsonWebSignature2020LdSigner;
import java.math.BigInteger;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;

/**
 * Test helper providing DID documents, EC key material and DID resolution results.
 */
public class DidTestHelper {

    public static final String DID = "did:web:example.com";
    public static final String VERIFICATION_METHOD = DID + "#key-1";

    private static final int P256_COORDINATE_LENGTH = 32;

    private DidTestHelper() {
    }

    /**
     * Generates a P-256 EC key pair.
     *
     * @return the generated key pair
     * @throws Exception if the key pair could not be generated
     */
    public static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Builds a DID document for the given public key and signs it with the matching private key.
     *
     * @param privateKey     the private key used to create the proof
     * @param publicKey      the public key embedded as verification method
     * @param documentLoader the document loader used to resolve the JSON-LD contexts
     * @return the signed DID document as JSON
     * @throws Exception if the DID document could not be signed
     */
    public static String signDidDocument(ECPrivateKey privateKey, ECPublicKey publicKey,
                                         DocumentLoader documentLoader) throws Exception {

        JsonLDObject didDocument = JsonLDObject.fromJson(buildUnsignedDidDocument(publicKey));
        didDocument.setDocumentLoader(documentLoader);

        JsonWebSignature2020LdSigner signer =
                new JsonWebSignature2020LdSigner(new Es256ByteSigner(privateKey));
        signer.setCreated(new Date());
        signer.setProofPurpose(LDSecurityKeywords.JSONLD_TERM_ASSERTIONMETHOD);
        signer.setVerificationMethod(URI.create(VERIFICATION_METHOD));

        signer.sign(didDocument);

        return didDocument.toJson();
    }

    /**
     * Builds an unsigned DID document exposing the given public key as JsonWebKey2020.
     *
     * @param publicKey the public key to embed
     * @return the unsigned DID document as JSON
     */
    public static String buildUnsignedDidDocument(ECPublicKey publicKey) {
        String x = encodeCoordinate(publicKey.getW().getAffineX());
        String y = encodeCoordinate(publicKey.getW().getAffineY());

        return """
                {
                  "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/jws-2020/v1"
                  ],
                  "id": "%s",
                  "verificationMethod": [
                    {
                      "id": "%s",
                      "type": "JsonWebKey2020",
                      "controller": "%s",
                      "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "%s",
                        "y": "%s"
                      }
                    }
                  ]
                }
                """.formatted(DID, VERIFICATION_METHOD, DID, x, y);
    }

    /**
     * Builds a DID document containing a proof, as expected by the trusted DID upload endpoint.
     *
     * @return the signed DID document as JSON
     */
    public static String buildUploadDidDocument() {
        return """
                {
                  "@context": ["https://www.w3.org/ns/did/v1"],
                  "id": "%s",
                  "controller": "%s",
                  "verificationMethod": [
                    {
                      "id": "%s",
                      "type": "JsonWebKey2020",
                      "controller": "%s",
                      "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "x-value",
                        "y": "y-value",
                        "x5c": ["certificate"]
                      }
                    }
                  ],
                  "proof": {
                    "type": "JsonWebSignature2020",
                    "created": "2024-01-01T00:00:00Z",
                    "proofPurpose": "assertionMethod",
                    "verificationMethod": "%s",
                    "jws": "eyJhbGciOiJFUzI1NiJ9..signature"
                  }
                }
                """.formatted(DID, DID, VERIFICATION_METHOD, DID, VERIFICATION_METHOD);
    }

    /**
     * Creates a failed DID resolution result reporting that the DID could not be found.
     *
     * @return the DID resolution result
     */
    public static DidResolutionResult notFoundResult() {
        return DidResolutionResult.error(DidResolutionMetadata.ERROR_NOT_FOUND, "DID not found");
    }

    /**
     * Creates a failed DID resolution result reporting that the DID is invalid.
     *
     * @return the DID resolution result
     */
    public static DidResolutionResult invalidDidResult() {
        return DidResolutionResult.error(DidResolutionMetadata.ERROR_INVALID_DID, "DID is invalid");
    }

    /**
     * Encodes an EC affine coordinate as fixed-length base64url value as required for a P-256 JWK.
     *
     * @param value the affine coordinate
     * @return the base64url encoded coordinate
     */
    public static String encodeCoordinate(BigInteger value) {
        byte[] bytes = value.toByteArray();
        byte[] coordinate = new byte[P256_COORDINATE_LENGTH];

        if (bytes.length > P256_COORDINATE_LENGTH) {
            System.arraycopy(bytes, bytes.length - P256_COORDINATE_LENGTH, coordinate, 0,
                    P256_COORDINATE_LENGTH);
        } else {
            System.arraycopy(bytes, 0, coordinate, P256_COORDINATE_LENGTH - bytes.length, bytes.length);
        }

        return Base64.getUrlEncoder().withoutPadding().encodeToString(coordinate);
    }

    /**
     * ES256 signer producing DER encoded ECDSA signatures with a P-256 private key.
     */
    public static class Es256ByteSigner extends ByteSigner {

        private final ECPrivateKey privateKey;

        public Es256ByteSigner(ECPrivateKey privateKey) {
            super(JWSAlgorithm.ES256.getName());
            this.privateKey = privateKey;
        }

        @Override
        protected byte[] sign(byte[] content) throws GeneralSecurityException {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);
            signature.update(content);
            return signature.sign();
        }
    }
}
