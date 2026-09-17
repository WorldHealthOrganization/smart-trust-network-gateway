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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import eu.europa.ec.dgc.did.DidResolver;
import eu.europa.ec.dgc.did.DidVerificationService;
import eu.europa.ec.dgc.did.model.DidDocument;
import eu.europa.ec.dgc.did.model.DidResolutionResult;
import eu.europa.ec.dgc.did.model.VerificationMethod;
import eu.europa.ec.dgc.gateway.client.cloudmersive.CloudmersiveClient;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.model.CloudmersiveThreatDetectionResponse;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.gateway.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.gateway.testdata.DidTestHelper;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class TrustedDidUploadIntegrationTest {

    private static final String DID = DidTestHelper.DID;
    private static final String VERIFICATION_METHOD = DidTestHelper.VERIFICATION_METHOD;
    private static final String COUNTRY = "DE";

    @MockBean
    DidResolver didResolver;

    @MockBean
    DidVerificationService didVerificationService;

    @MockBean
    CloudmersiveClient cloudmersiveClient;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    SignerInformationRepository signerInformationRepository;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    CertificateUtils certificateUtils;

    private X509Certificate uploadedCertificate;
    private String encodedUploadedCertificate;

    @BeforeEach
    void setup() throws Exception {
        signerInformationRepository.deleteAll();

        CloudmersiveThreatDetectionResponse threatResponse = new CloudmersiveThreatDetectionResponse();
        threatResponse.setCleanResult(true);
        when(cloudmersiveClient.detectThreatInString(any())).thenReturn(threatResponse);

        // Onboard the participant so its UP.pem can be resolved as signer certificate
        trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, COUNTRY);

        KeyPair uploadedKeyPair = DidTestHelper.generateEcKeyPair();
        uploadedCertificate = CertificateTestUtils.generateCertificate(uploadedKeyPair, COUNTRY, "DSC to import");
        encodedUploadedCertificate = Base64.getEncoder().encodeToString(uploadedCertificate.getEncoded());

        mockDidResolution();
    }

    @Test
    void testVerifiedDidDocumentIsStoredAsSignerInformation() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        mockMvc.perform(post("/trusted-did")
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "\"participant\": {\"code\": \"DE\"},")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.verified").value(true));

        List<SignerInformationEntity> stored = signerInformationRepository.findAll();
        Assertions.assertEquals(1, stored.size(), "Verified DID document was not stored.");

        SignerInformationEntity entity = stored.get(0);
        Assertions.assertEquals(SignerInformationEntity.SourceType.DID, entity.getSourceType());
        Assertions.assertEquals(COUNTRY, entity.getCountry());
        Assertions.assertEquals(SignerInformationEntity.CertificateType.DSC, entity.getCertificateType());
        Assertions.assertEquals(encodedUploadedCertificate, entity.getRawData(),
            "Raw data must be the x5c value, not the array.");
        Assertions.assertEquals(
            certificateUtils.getCertThumbprint(new X509CertificateHolder(uploadedCertificate.getEncoded())),
            entity.getThumbprint());

        // Default values for the remaining columns
        Assertions.assertEquals("DCC", entity.getDomain());
        Assertions.assertNull(entity.getKid());
        Assertions.assertNull(entity.getProperties());
        Assertions.assertNull(entity.getSourceGateway());

        String decodedSignature = new String(Base64.getDecoder().decode(entity.getSignature()),
            StandardCharsets.UTF_8);
        Assertions.assertTrue(decodedSignature.contains(DID),
            "Signature must be the Base64 encoded uploaded DID document.");
    }

    @Test
    void testUnverifiedDidDocumentIsNotStored() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(false);

        mockMvc.perform(post("/trusted-did")
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "\"participant\": {\"code\": \"DE\"},")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.verified").value(false));

        Assertions.assertTrue(signerInformationRepository.findAll().isEmpty(),
            "Unverified DID document must not be stored.");
    }

    @Test
    void testDidDocumentWithoutParticipantCodeIsRejected() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        mockMvc.perform(post("/trusted-did")
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "")))
            .andExpect(status().isBadRequest());

        Assertions.assertTrue(signerInformationRepository.findAll().isEmpty(),
            "Nothing must be stored when the participant code is missing.");
    }

    @Test
    void testDidDocumentOfNotOnboardedParticipantIsRejected() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        mockMvc.perform(post("/trusted-did")
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "\"participant\": {\"code\": \"XY\"},")))
            .andExpect(status().isBadRequest());

        Assertions.assertTrue(signerInformationRepository.findAll().isEmpty(),
            "Nothing must be stored for a participant without upload certificate.");
    }

    @Test
    void testAlpha3ParticipantCodeIsMappedToAlpha2Country() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);
        trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XA");

        mockMvc.perform(post("/trusted-did")
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "\"participant\": {\"code\": \"XXA\"},")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.verified").value(true));

        List<SignerInformationEntity> stored = signerInformationRepository.findAll();
        Assertions.assertEquals(1, stored.size());
        Assertions.assertEquals("XA", stored.get(0).getCountry(),
            "Alpha-3 participant code must be mapped to the configured virtual country.");
        Assertions.assertEquals(SignerInformationEntity.SourceType.DID, stored.get(0).getSourceType());
    }

    @Test
    void testFragmentPrefixedParticipantCodeIsAccepted() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);
        trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XA");

        // TNG publishes the participant code as DID fragment reference, e.g. "#XXA"
        mockMvc.perform(post("/trusted-did")
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "\"participant\": {\"code\": \"#XXA\"},")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.verified").value(true));

        List<SignerInformationEntity> stored = signerInformationRepository.findAll();
        Assertions.assertEquals(1, stored.size(), "Fragment prefixed participant code was not stored.");
        Assertions.assertEquals("XA", stored.get(0).getCountry());
    }

    @Test
    void testFragmentPrefixedAlpha2ParticipantCodeIsAccepted() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        mockMvc.perform(post("/trusted-did")
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "\"participant\": {\"code\": \"#DE\"},")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.verified").value(true));

        List<SignerInformationEntity> stored = signerInformationRepository.findAll();
        Assertions.assertEquals(1, stored.size());
        Assertions.assertEquals(COUNTRY, stored.get(0).getCountry());
    }


    @Test
    void testFragmentPrefixesAreStrippedFromAllCodedValues() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);
        trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XA");

        String codedValues = """
            "domain": {"code": "#DCC"},
            "participant": {"code": "#XXA"},
            "keyusage": {"code": "#CSCA"},
            """;

        mockMvc.perform(post("/trusted-did")
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, codedValues)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.verified").value(true));

        List<SignerInformationEntity> stored = signerInformationRepository.findAll();
        Assertions.assertEquals(1, stored.size());
        Assertions.assertEquals("XA", stored.get(0).getCountry(), "Participant '#' must be stripped.");
        Assertions.assertEquals("DCC", stored.get(0).getDomain(), "Domain '#' must be stripped.");
    }

    @Test
    void testAlreadyStoredCertificateIsRejected() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        String didDocument =
            buildUploadDidDocument(encodedUploadedCertificate, "\"participant\": {\"code\": \"DE\"},");

        mockMvc.perform(post("/trusted-did")
                .contentType(MediaType.valueOf("application/did"))
                .content(didDocument))
            .andExpect(status().isOk());

        mockMvc.perform(post("/trusted-did")
                .contentType(MediaType.valueOf("application/did"))
                .content(didDocument))
            .andExpect(status().isBadRequest());

        Assertions.assertEquals(1, signerInformationRepository.findAll().size(),
            "Certificate must not be stored twice.");
    }

    private void mockDidResolution() throws Exception {
        KeyPair proofKeyPair = DidTestHelper.generateEcKeyPair();
        ECPublicKey proofPublicKey = (ECPublicKey) proofKeyPair.getPublic();

        VerificationMethod verificationMethod = new VerificationMethod();
        verificationMethod.setId(VERIFICATION_METHOD);
        verificationMethod.setType("JsonWebKey2020");
        verificationMethod.setController(DID);
        verificationMethod.setPublicKeyJwk(Map.of(
            "kty", "EC",
            "crv", "P-256",
            "x", DidTestHelper.encodeCoordinate(proofPublicKey.getW().getAffineX()),
            "y", DidTestHelper.encodeCoordinate(proofPublicKey.getW().getAffineY())
        ));

        DidDocument resolvedDidDocument = new DidDocument();
        resolvedDidDocument.setId(DID);
        resolvedDidDocument.setVerificationMethod(List.of(verificationMethod));

        when(didResolver.resolve(anyString())).thenReturn(DidResolutionResult.success(resolvedDidDocument));
    }

    private String buildUploadDidDocument(String encodedCertificate, String participantProperty) {
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
                  %s
                  "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "x-value",
                    "y": "y-value",
                    "x5c": ["%s"]
                  }
                }
              ],
              "proof": {
                "type": "JsonWebSignature2020",
                "created": "2024-01-01T00:00:00Z",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "%s",
                "jws": "******"
              }
            }
            """.formatted(DID, DID, VERIFICATION_METHOD, DID, participantProperty, encodedCertificate,
                VERIFICATION_METHOD);
    }
}
