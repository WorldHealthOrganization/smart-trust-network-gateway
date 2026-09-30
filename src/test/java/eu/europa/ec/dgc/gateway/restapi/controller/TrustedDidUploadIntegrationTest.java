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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import eu.europa.ec.dgc.did.DidResolver;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
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
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest
@AutoConfigureMockMvc
class TrustedDidUploadIntegrationTest {

    private static final String AUTH_COUNTRY = "EU";

    private static final String DID = DidTestHelper.DID;
    private static final String VERIFICATION_METHOD = DidTestHelper.VERIFICATION_METHOD;
    private static final String COUNTRY = "DE";

    private static final String TNG_PROOF_VERIFICATION_METHOD =
        "did:web:raw.githubusercontent.com:WorldHealthOrganization:tng-participants-dev:main:WHO:signing:DID";
    private static final String TNG_DSC_1_THUMBPRINT_PREFIX = "506046f9059d79a7";
    private static final String TNG_DSC_2_THUMBPRINT_PREFIX = "c3e0ec1d22d3e98d";
    private static final String TNG_CSCA_THUMBPRINT_PREFIX = "f15407bee795346a";

    /**
     * The CSCA which is x5c[1] of both verification methods in tng-multi-verification-method-did.json.
     */
    private static final String TNG_CSCA = "MIICwjCCAmegAwIBAgIUcIoY3jailJnpPEdH/qYF6/O+HewwCgYIKoZIzj0EAwIwgbwxCzAJBgNVBAYTAkFEMRcwFQYDVQQIDA5ERVYgQ291bnRyeSBBRDEbMBkGA1UEBwwSRXNjYWxkZXMtRW5nb3JkYW55MUIwQAYDVQQKDDlBbmRvcnJhIEhlYWx0aGNhcmUtU2VydmVpIEFuZG9ycmEgZEF0ZW5jaW8gU2FuaXRhcmlhLVNBQVMxHDAaBgNVBAsME1NTSUktSW5mb3JtYXRpY2EtVEkxFTATBgNVBAMMDE5hdGlvbkFEX1ROUDAeFw0yNTA5MjkxNTAzNTBaFw0yOTA5MjkxNTAzNTBaMIG8MQswCQYDVQQGEwJBRDEXMBUGA1UECAwOREVWIENvdW50cnkgQUQxGzAZBgNVBAcMEkVzY2FsZGVzLUVuZ29yZGFueTFCMEAGA1UECgw5QW5kb3JyYSBIZWFsdGhjYXJlLVNlcnZlaSBBbmRvcnJhIGRBdGVuY2lvIFNhbml0YXJpYS1TQUFTMRwwGgYDVQQLDBNTU0lJLUluZm9ybWF0aWNhLVRJMRUwEwYDVQQDDAxOYXRpb25BRF9UTlAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARBSL8auWpJIMN5rlT53gc6Oj/up3JDN2sYynXjn0i8FD/hbK0j34g18STJTPRhkLOF4QJUMyilzi8bUihMNusXo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUtvWX86Z6t2FU0TZwm11mhoeAFQQwCgYIKoZIzj0EAwIDSQAwRgIhAJmn/ks5HUld7Uo/rY25+LnAbF/6xLV1vGaB/rF5pjSvAiEA7AhHZ2j+z6G6y9gRDmn/mpVFDTmosDGwbVAdMjX9B1c=";

    @MockBean
    DidResolver didResolver;

    @MockBean
    DidVerificationService didVerificationService;

    @MockBean
    CloudmersiveClient cloudmersiveClient;

    @Autowired
    DgcConfigProperties dgcConfigProperties;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    SignerInformationRepository signerInformationRepository;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    CertificateUtils certificateUtils;

    private ECPublicKey uploadedPublicKey;
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
        uploadedPublicKey = (ECPublicKey) uploadedKeyPair.getPublic();
        uploadedCertificate = CertificateTestUtils.generateCertificate(uploadedKeyPair, COUNTRY, "DSC to import");
        encodedUploadedCertificate = Base64.getEncoder().encodeToString(uploadedCertificate.getEncoded());

        mockDidResolution();
    }

    @Test
    void testVerifiedDidDocumentIsStoredAsSignerInformation() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        mockMvc.perform(authenticated(put("/trusted-did"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "\"participant\": {\"code\": \"DE\"},")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.verified").value(true))
            .andExpect(jsonPath("$.stored").value(true))
            .andExpect(jsonPath("$.storedCertificates").value(1))
            .andExpect(jsonPath("$.message").value("verified, stored 1 certificate(s)"));

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

        mockMvc.perform(authenticated(put("/trusted-did"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "\"participant\": {\"code\": \"DE\"},")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.verified").value(false))
            .andExpect(jsonPath("$.stored").value(false))
            .andExpect(jsonPath("$.storedCertificates").value(0))
            .andExpect(jsonPath("$.message").value("not verified, no certificates stored"));

        Assertions.assertTrue(signerInformationRepository.findAll().isEmpty(),
            "Unverified DID document must not be stored.");
    }

    @Test
    void testDidDocumentWithoutParticipantCodeIsRejected() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        mockMvc.perform(authenticated(put("/trusted-did"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "")))
            .andExpect(status().isBadRequest());

        Assertions.assertTrue(signerInformationRepository.findAll().isEmpty(),
            "Nothing must be stored when the participant code is missing.");
    }

    @Test
    void testDidDocumentOfNotOnboardedParticipantIsRejected() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        mockMvc.perform(authenticated(put("/trusted-did"))
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

        mockMvc.perform(authenticated(put("/trusted-did"))
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
        mockMvc.perform(authenticated(put("/trusted-did"))
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

        mockMvc.perform(authenticated(put("/trusted-did"))
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

        mockMvc.perform(authenticated(put("/trusted-did"))
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
    void testPathVariablesAreUsedWhenCodedValuesAreMissing() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);
        trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XA");

        // Document carries no domain/participant/keyusage at all
        mockMvc.perform(authenticated(put("/trusted-did/DDCC/XXA/CSCA"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.verified").value(true));

        List<SignerInformationEntity> stored = signerInformationRepository.findAll();
        Assertions.assertEquals(1, stored.size(), "Path variables were not applied.");
        Assertions.assertEquals("XA", stored.get(0).getCountry());
        Assertions.assertEquals("DDCC", stored.get(0).getDomain());
        Assertions.assertEquals(SignerInformationEntity.SourceType.DID, stored.get(0).getSourceType());
    }

    @Test
    void testPathVariablesDoNotOverrideValuesFromDocument() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        String codedValues = """
            "domain": {"code": "#DCC"},
            "participant": {"code": "#DEU"},
            """;

        mockMvc.perform(authenticated(put("/trusted-did/DDCC/XXA/CSCA"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, codedValues)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.verified").value(true));

        List<SignerInformationEntity> stored = signerInformationRepository.findAll();
        Assertions.assertEquals(1, stored.size());
        Assertions.assertEquals(COUNTRY, stored.get(0).getCountry(),
            "Participant of the document must win over the path variable.");
        Assertions.assertEquals("DCC", stored.get(0).getDomain(),
            "Domain of the document must win over the path variable.");
    }

    @Test
    void testPathVariablesAreNotAppliedWhenProofIsNotVerified() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(false);
        trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XA");

        mockMvc.perform(authenticated(put("/trusted-did/DDCC/XXA/CSCA"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.verified").value(false))
            .andExpect(jsonPath("$.stored").value(false))
            .andExpect(jsonPath("$.storedCertificates").value(0))
            .andExpect(jsonPath("$.message").value("not verified, no certificates stored"));

        Assertions.assertTrue(signerInformationRepository.findAll().isEmpty(),
            "Unverified DID document must not be stored.");
    }

    @Test
    void testStorageOnlyHappensWhenProofIsVerified() throws Exception {
        String document = buildUploadDidDocument(encodedUploadedCertificate, "\"participant\": {\"code\": \"DE\"},");

        // First attempt with a proof which cannot be verified must leave the database untouched
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(false);

        mockMvc.perform(authenticated(put("/trusted-did"))
                .contentType(MediaType.valueOf("application/did"))
                .content(document))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.stored").value(false));

        Assertions.assertTrue(signerInformationRepository.findAll().isEmpty(),
            "Nothing must be stored while the proof is not verified.");

        // The very same document is stored as soon as the proof verifies
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        mockMvc.perform(authenticated(put("/trusted-did"))
                .contentType(MediaType.valueOf("application/did"))
                .content(document))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.stored").value(true))
            .andExpect(jsonPath("$.storedCertificates").value(1));

        Assertions.assertEquals(1, signerInformationRepository.findAll().size(),
            "Verified DID document must be stored.");
    }

    @Test
    void testExistingDidCertificateIsReplaced() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        mockMvc.perform(authenticated(put("/trusted-did"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate,
                    "\"domain\": {\"code\": \"#DCC\"}, \"participant\": {\"code\": \"DE\"},")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.stored").value(true));

        SignerInformationEntity first = signerInformationRepository.findAll().get(0);
        ZonedDateTime firstCreatedAt = first.getCreatedAt();
        Thread.sleep(10);

        mockMvc.perform(authenticated(put("/trusted-did"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate,
                    "\"domain\": {\"code\": \"#DDCC\"}, \"participant\": {\"code\": \"DE\"},")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.stored").value(true))
            .andExpect(jsonPath("$.storedCertificates").value(1));

        List<SignerInformationEntity> stored = signerInformationRepository.findAll();
        Assertions.assertEquals(1, stored.size(), "Existing record must be replaced, not duplicated.");

        SignerInformationEntity replaced = stored.get(0);
        Assertions.assertEquals(first.getId(), replaced.getId(), "DID entry must be replaced in place.");
        Assertions.assertEquals(first.getUuid(), replaced.getUuid());
        Assertions.assertEquals(first.getVersion() + 1, replaced.getVersion(), "Version must be increased.");
        Assertions.assertTrue(replaced.getCreatedAt().isAfter(firstCreatedAt), "created_at must be reset.");
        Assertions.assertEquals("DDCC", replaced.getDomain(), "Values of the latest upload must be stored.");
        Assertions.assertEquals(SignerInformationEntity.SourceType.DID, replaced.getSourceType());
    }

    @Test
    void testExistingCmsCertificateIsRemovedAndReplacedByDidEntry() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        SignerInformationEntity cmsEntity = new SignerInformationEntity();
        cmsEntity.setCountry(COUNTRY);
        cmsEntity.setRawData(encodedUploadedCertificate);
        cmsEntity.setThumbprint(
            certificateUtils.getCertThumbprint(new X509CertificateHolder(uploadedCertificate.getEncoded())));
        cmsEntity.setCertificateType(SignerInformationEntity.CertificateType.DSC);
        cmsEntity.setSignature("cms-signature");
        cmsEntity.setKid("cmsKid");
        cmsEntity.setSourceType(SignerInformationEntity.SourceType.CMS);
        cmsEntity = signerInformationRepository.save(cmsEntity);

        mockMvc.perform(authenticated(put("/trusted-did"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate,
                    "\"domain\": {\"code\": \"#DDCC\"}, \"participant\": {\"code\": \"DE\"},")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.stored").value(true))
            .andExpect(jsonPath("$.storedCertificates").value(1));

        List<SignerInformationEntity> stored = signerInformationRepository.findAll();
        Assertions.assertEquals(1, stored.size(), "CMS entry must be removed, not duplicated.");

        SignerInformationEntity didEntity = stored.get(0);
        Assertions.assertNotEquals(cmsEntity.getId(), didEntity.getId(), "A new DID entry must be inserted.");
        Assertions.assertFalse(signerInformationRepository.findById(cmsEntity.getId()).isPresent());
        Assertions.assertEquals(SignerInformationEntity.SourceType.DID, didEntity.getSourceType());
        Assertions.assertEquals(1, didEntity.getVersion());
        Assertions.assertEquals("DDCC", didEntity.getDomain());
        Assertions.assertNull(didEntity.getKid(), "CMS specific values must not be carried over.");
        Assertions.assertNotEquals("cms-signature", didEntity.getSignature());
    }

    @Test
    void testPostIsNoLongerSupported() throws Exception {
        // CertificateAuthenticationFilter turns unmatched methods into 401 before Spring MVC can answer 405
        mockMvc.perform(post("/trusted-did")
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "\"participant\": {\"code\": \"DE\"},")))
            .andExpect(status().is4xxClientError());

        Assertions.assertTrue(signerInformationRepository.findAll().isEmpty());
    }

    @Test
    void testEveryVerificationMethodOfTngDocumentIsStored() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);
        trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "AD");
        mockDidResolution(TNG_PROOF_VERIFICATION_METHOD);

        String didDocument = readResource("did/tng-multi-verification-method-did.json");

        mockMvc.perform(authenticated(put("/trusted-did"))
                .contentType(MediaType.valueOf("application/did"))
                .content(didDocument))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.stored").value(true))
            .andExpect(jsonPath("$.storedCertificates").value(2))
            .andExpect(jsonPath("$.message").value("verified, stored 2 certificate(s)"));

        List<SignerInformationEntity> stored = signerInformationRepository.findAll();
        Assertions.assertEquals(
            Set.of(TNG_DSC_1_THUMBPRINT_PREFIX, TNG_DSC_2_THUMBPRINT_PREFIX),
            stored.stream().map(e -> e.getThumbprint().substring(0, 16)).collect(Collectors.toSet()),
            "Exactly x5c[0] of each verification method must be stored.");
        Assertions.assertTrue(stored.stream().noneMatch(e -> e.getThumbprint().startsWith(TNG_CSCA_THUMBPRINT_PREFIX)),
            "The CSCA of the x5c chain must not be stored as signer information.");

        for (SignerInformationEntity entity : stored) {
            Assertions.assertEquals("AD", entity.getCountry());
            Assertions.assertEquals("DCC", entity.getDomain());
            Assertions.assertEquals(SignerInformationEntity.CertificateType.DSC, entity.getCertificateType());
            Assertions.assertEquals(SignerInformationEntity.SourceType.DID, entity.getSourceType());
            Assertions.assertEquals(1, entity.getVersion());
            Assertions.assertTrue(entity.getSignature().length() > 6000,
                "Whole document must be stored even though it exceeds the former VARCHAR(6000).");

            String storedDocument = new String(Base64.getDecoder().decode(entity.getSignature()),
                StandardCharsets.UTF_8);
            Assertions.assertTrue(storedDocument.contains("\"kid\":\"UGBG+QWdeac=\""),
                "The kid of the JWK must be preserved.");
        }
    }

    @Test
    void testReUploadOfTngDocumentReplacesEveryVerificationMethod() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);
        trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "AD");
        mockDidResolution(TNG_PROOF_VERIFICATION_METHOD);

        String didDocument = readResource("did/tng-multi-verification-method-did.json");

        for (int i = 0; i < 2; i++) {
            mockMvc.perform(authenticated(put("/trusted-did"))
                    .contentType(MediaType.valueOf("application/did"))
                    .content(didDocument))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.storedCertificates").value(2));
        }

        List<SignerInformationEntity> stored = signerInformationRepository.findAll();
        Assertions.assertEquals(2, stored.size());
        Assertions.assertTrue(stored.stream().allMatch(e -> e.getVersion() == 2),
            "Every verification method must be replaced on re-upload.");
    }

    @Test
    void testCaCertificateAsFirstX5cEntryIsRejected() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        mockMvc.perform(authenticated(put("/trusted-did"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(TNG_CSCA, "\"participant\": {\"code\": \"DE\"},")))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.details").value(org.hamcrest.Matchers.containsString("is a CA certificate")));

        Assertions.assertTrue(signerInformationRepository.findAll().isEmpty());
    }

    @Test
    void testCertificateNotMatchingJwkIsRejected() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);

        X509Certificate otherCertificate =
            CertificateTestUtils.generateCertificate(DidTestHelper.generateEcKeyPair(), COUNTRY, "Other DSC");

        mockMvc.perform(authenticated(put("/trusted-did"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(Base64.getEncoder().encodeToString(otherCertificate.getEncoded()),
                    "\"participant\": {\"code\": \"DE\"},")))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.details").value(org.hamcrest.Matchers.containsString("does not match the JWK")));

        Assertions.assertTrue(signerInformationRepository.findAll().isEmpty());
    }

    @Test
    void testGetTrustedDidReturnsUploadedDocument() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);
        trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XA");

        mockMvc.perform(authenticated(put("/trusted-did/DDCC/XXA/CSCA"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.stored").value(true));

        for (String path : List.of("/trusted-did/DDCC/XXA/CSCA", "/trusted-did/ddcc/XA/csca")) {
            mockMvc.perform(authenticated(get(path)))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.valueOf("application/did+ld+json")))
                .andExpect(jsonPath("$.id").value(DID))
                .andExpect(jsonPath("$.verificationMethod[0].id").value(VERIFICATION_METHOD))
                .andExpect(jsonPath("$.verificationMethod[0].domain.code").value("#DDCC"))
                .andExpect(jsonPath("$.verificationMethod[0].participant.code").value("#XXA"))
                .andExpect(jsonPath("$.verificationMethod[0].keyusage.code").value("#CSCA"))
                .andExpect(jsonPath("$.verificationMethod[0].publicKeyJwk.x5c[0]").value(encodedUploadedCertificate))
                .andExpect(jsonPath("$.proof.verificationMethod").value(VERIFICATION_METHOD));
        }
    }

    @Test
    void testGetTrustedDidReturnsNotFoundForUnknownCriteria() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);
        trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XA");

        mockMvc.perform(authenticated(put("/trusted-did/DDCC/XXA/CSCA"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "")))
            .andExpect(status().isOk());

        mockMvc.perform(authenticated(get("/trusted-did/DDCC/XXA/DSC"))).andExpect(status().isNotFound());
        mockMvc.perform(authenticated(get("/trusted-did/DCC/XXA/CSCA"))).andExpect(status().isNotFound());
        mockMvc.perform(authenticated(get("/trusted-did/DDCC/DEU/CSCA"))).andExpect(status().isNotFound());
    }

    @Test
    void testGetTrustedDidRejectsInvalidCountry() throws Exception {
        mockMvc.perform(authenticated(get("/trusted-did/DDCC/INVALID/CSCA"))).andExpect(status().isBadRequest());
    }

    @Test
    void testDeleteTrustedDidRemovesAllMatchingEntries() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);
        trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XA");

        mockMvc.perform(authenticated(put("/trusted-did/DDCC/XXA/CSCA"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "")))
            .andExpect(status().isOk());

        // Second upload with a different certificate for the same domain, country and type
        KeyPair secondKeyPair = DidTestHelper.generateEcKeyPair();
        uploadedPublicKey = (ECPublicKey) secondKeyPair.getPublic();
        encodedUploadedCertificate = Base64.getEncoder().encodeToString(
            CertificateTestUtils.generateCertificate(secondKeyPair, COUNTRY, "Second DSC").getEncoded());

        mockMvc.perform(authenticated(put("/trusted-did/DDCC/XXA/CSCA"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "")))
            .andExpect(status().isOk());
        Assertions.assertEquals(2, signerInformationRepository.findAll().size());

        mockMvc.perform(authenticated(delete("/trusted-did/ddcc/xxa/csca"))).andExpect(status().isNoContent());

        Assertions.assertTrue(signerInformationRepository.findAll().isEmpty(),
            "All entries matching the path variables must be deleted.");
        mockMvc.perform(authenticated(get("/trusted-did/DDCC/XXA/CSCA"))).andExpect(status().isNotFound());
        mockMvc.perform(authenticated(delete("/trusted-did/DDCC/XXA/CSCA"))).andExpect(status().isNotFound());
    }

    @Test
    void testTrustedDidEndpointsRequireAuthentication() throws Exception {
        String document = buildUploadDidDocument(encodedUploadedCertificate, "\"participant\": {\"code\": \"DE\"},");

        mockMvc.perform(put("/trusted-did")
                .contentType(MediaType.valueOf("application/did"))
                .content(document))
            .andExpect(status().isUnauthorized());
        mockMvc.perform(put("/trusted-did/DDCC/XXA/CSCA")
                .contentType(MediaType.valueOf("application/did"))
                .content(document))
            .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/trusted-did/DDCC/XXA/CSCA")).andExpect(status().isUnauthorized());
        mockMvc.perform(delete("/trusted-did/DDCC/XXA/CSCA")).andExpect(status().isUnauthorized());

        Assertions.assertTrue(signerInformationRepository.findAll().isEmpty());
    }

    @Test
    void testDeleteTrustedDidKeepsNonMatchingCertificates() throws Exception {
        when(didVerificationService.verify(anyString(), any(PublicKey.class))).thenReturn(true);
        trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XA");

        mockMvc.perform(authenticated(put("/trusted-did/DDCC/XXA/CSCA"))
                .contentType(MediaType.valueOf("application/did"))
                .content(buildUploadDidDocument(encodedUploadedCertificate, "")))
            .andExpect(status().isOk());

        mockMvc.perform(authenticated(delete("/trusted-did/DDCC/XXA/DSC"))).andExpect(status().isNotFound());
        mockMvc.perform(authenticated(delete("/trusted-did/DCC/XXA/CSCA"))).andExpect(status().isNotFound());
        mockMvc.perform(authenticated(delete("/trusted-did/DDCC/DEU/CSCA"))).andExpect(status().isNotFound());
        mockMvc.perform(authenticated(delete("/trusted-did/DDCC/INVALID/CSCA"))).andExpect(status().isBadRequest());

        Assertions.assertEquals(1, signerInformationRepository.findAll().size(),
            "Non matching certificates must not be deleted.");
    }

    private String readResource(String path) throws Exception {
        try (var stream = getClass().getClassLoader().getResourceAsStream(path)) {
            Assertions.assertNotNull(stream, "Missing test resource " + path);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private void mockDidResolution() throws Exception {
        mockDidResolution(VERIFICATION_METHOD);
    }

    private void mockDidResolution(String verificationMethodId) throws Exception {
        KeyPair proofKeyPair = DidTestHelper.generateEcKeyPair();
        ECPublicKey proofPublicKey = (ECPublicKey) proofKeyPair.getPublic();

        VerificationMethod verificationMethod = new VerificationMethod();
        verificationMethod.setId(verificationMethodId);
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
                    "x": "%s",
                    "y": "%s",
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
            """.formatted(DID, DID, VERIFICATION_METHOD, DID, participantProperty,
                DidTestHelper.encodeCoordinate(uploadedPublicKey.getW().getAffineX()),
                DidTestHelper.encodeCoordinate(uploadedPublicKey.getW().getAffineY()),
                encodedCertificate, VERIFICATION_METHOD);
    }

    private MockHttpServletRequestBuilder authenticated(MockHttpServletRequestBuilder builder) throws Exception {
        return builder
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getThumbprint(),
                trustedPartyTestHelper.getHash(TrustedPartyEntity.CertificateType.AUTHENTICATION, AUTH_COUNTRY))
            .header(dgcConfigProperties.getCertAuth().getHeaderFields().getDistinguishedName(), "C=" + AUTH_COUNTRY);
    }
}
