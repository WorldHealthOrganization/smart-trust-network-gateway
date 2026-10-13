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

package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.client.cloudmersive.CloudmersiveClient;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.model.CloudmersiveThreatDetectionResponse;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.gateway.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.gateway.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.gateway.testdata.TrustedPartyTestHelper;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@SpringBootTest
class SignerInformationServiceTest {

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    DgcTestKeyStore dgcTestKeyStore;

    @Autowired
    TrustedPartyTestHelper trustedPartyTestHelper;

    @Autowired
    SignerInformationRepository signerInformationRepository;

    @Autowired
    SignerInformationService signerInformationService;

    @MockBean
    CloudmersiveClient cloudmersiveClient;

    private static final String countryCode = "EU";
    private static final String dummySignature = "randomStringAsSignatureWhichIsNotValidatedInServiceLevel";

    @BeforeEach
    void setup() {
        CloudmersiveThreatDetectionResponse threatResponse = new CloudmersiveThreatDetectionResponse();
        threatResponse.setCleanResult(true);
        when(cloudmersiveClient.detectThreatInString(any())).thenReturn(threatResponse);
    }

    @AfterEach
    void cleanUp() {
        signerInformationRepository.deleteAll();
    }

    @Test
    void testAddingFailedConflict() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        X509Certificate cscaCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate =
            CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate,
                cscaPrivateKey);

        signerInformationService.addSignerCertificate(
            new X509CertificateHolder(payloadCertificate.getEncoded()),
            new X509CertificateHolder(signerCertificate.getEncoded()),
            dummySignature,
            countryCode
        );

        try {
            signerInformationService.addSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                dummySignature,
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.ALREADY_EXIST_CHECK_FAILED,
                e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb + 1, signerInformationRepository.count());
    }

    @Test
    void testAddingFailedKidConflict() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        X509Certificate cscaCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate =
            CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate,
                cscaPrivateKey);

        signerInformationService.addSignerCertificate(
            new X509CertificateHolder(payloadCertificate.getEncoded()),
            new X509CertificateHolder(signerCertificate.getEncoded()),
            dummySignature,
            countryCode
        );

        Optional<SignerInformationEntity> certInDbOptional =
            signerInformationRepository.getFirstByThumbprint(certificateUtils.getCertThumbprint(payloadCertificate));

        Assertions.assertTrue(certInDbOptional.isPresent());

        SignerInformationEntity certInDb = certInDbOptional.get();
        certInDb.setThumbprint(certInDb.getThumbprint().substring(0, 40) +
            "x".repeat(24)); // Generate new Hash with first 40 chars from ogirinal hash and add 24 x

        signerInformationRepository.save(certInDb);

        try {
            signerInformationService.addSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                dummySignature,
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.KID_CHECK_FAILED,
                e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb + 1, signerInformationRepository.count());
    }

    @Test
    void testCmsUploadSupersedesDidEntryOfSameCountry() throws Exception {
        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate payloadCertificate = generatePayloadCertificate();
        String thumbprint = certificateUtils.getCertThumbprint(payloadCertificate);

        // KID equals the default CMS KID to ensure the superseded entry does not cause a KID conflict
        SignerInformationEntity didEntity = saveDidEntity(payloadCertificate, countryCode, thumbprint.substring(0, 16));

        SignerInformationEntity cmsEntity = signerInformationService.addSignerCertificate(
            new X509CertificateHolder(payloadCertificate.getEncoded()),
            new X509CertificateHolder(signerCertificate.getEncoded()),
            dummySignature,
            countryCode
        );

        Assertions.assertEquals(1, signerInformationRepository.count(), "DID entry must be replaced, not duplicated.");
        Assertions.assertFalse(signerInformationRepository.findById(didEntity.getId()).isPresent());
        SignerInformationEntity stored = signerInformationRepository.getFirstByThumbprint(thumbprint).orElseThrow();
        Assertions.assertEquals(cmsEntity.getId(), stored.getId());
        Assertions.assertEquals(SignerInformationEntity.SourceType.CMS, stored.getSourceType());
        Assertions.assertEquals(dummySignature, stored.getSignature());
    }

    @Test
    void testCmsUploadDoesNotSupersedeDidEntryOfAnotherCountry() throws Exception {
        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate payloadCertificate = generatePayloadCertificate();

        SignerInformationEntity didEntity = saveDidEntity(payloadCertificate, "XX", "didKid");

        SignerInformationService.SignerCertCheckException e = Assertions.assertThrows(
            SignerInformationService.SignerCertCheckException.class,
            () -> signerInformationService.addSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                dummySignature,
                countryCode));

        Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.ALREADY_EXIST_CHECK_FAILED,
            e.getReason());
        SignerInformationEntity stored = signerInformationRepository.findById(didEntity.getId()).orElseThrow();
        Assertions.assertEquals(SignerInformationEntity.SourceType.DID, stored.getSourceType());
        Assertions.assertEquals(1, signerInformationRepository.count());
    }

    private X509Certificate generatePayloadCertificate() throws Exception {
        X509Certificate cscaCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        return CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate,
            cscaPrivateKey);
    }

    private SignerInformationEntity saveDidEntity(X509Certificate certificate, String country, String kid)
        throws Exception {
        SignerInformationEntity didEntity = new SignerInformationEntity();
        didEntity.setCountry(country);
        didEntity.setRawData(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        didEntity.setThumbprint(certificateUtils.getCertThumbprint(certificate));
        didEntity.setCertificateType(SignerInformationEntity.CertificateType.DSC);
        didEntity.setSignature("did-signature");
        didEntity.setKid(kid);
        didEntity.setSourceType(SignerInformationEntity.SourceType.DID);
        return signerInformationRepository.save(didEntity);
    }

    @Test
    void testUploadFailedInvalidCSCA() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        // sign with TrustAnchor
        X509Certificate cscaCertificate = dgcTestKeyStore.getTrustAnchor();
        PrivateKey cscaPrivateKey = dgcTestKeyStore.getTrustAnchorPrivateKey();

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate =
            CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate,
                cscaPrivateKey);

        try {
            signerInformationService.addSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                dummySignature,
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.CSCA_CHECK_FAILED,
                e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testUploadFailedInvalidCSCAWrongCountryCode() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        // sign with CSCA from another country
        X509Certificate cscaCertificate = trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, "XX");
        PrivateKey cscaPrivateKey = trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, "XX");


        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate =
            CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate,
                cscaPrivateKey);

        try {
            signerInformationService.addSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                dummySignature,
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.CSCA_CHECK_FAILED,
                e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testUploadFailedPayloadCertCountryWrong() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);

        X509Certificate cscaCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate =
            CertificateTestUtils.generateCertificate(payloadKeyPair, "XX", "Payload Cert", cscaCertificate,
                cscaPrivateKey);

        try {
            signerInformationService.addSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                dummySignature,
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(
                SignerInformationService.SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED, e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testUploadFailedWrongSignerCertificate() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XX");

        X509Certificate cscaCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate =
            CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate,
                cscaPrivateKey);

        try {
            signerInformationService.addSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                dummySignature,
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.UPLOADER_CERT_CHECK_FAILED,
                e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testDeleteFailedNotExists() throws Exception {
        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate cscaCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate =
            CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate,
                cscaPrivateKey);

        try {
            signerInformationService.deleteSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.EXIST_CHECK_FAILED,
                e.getReason());
        }
    }

    @Test
    void testDeleteFailedPayloadCertCountryWrong() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, countryCode);
        X509Certificate cscaCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate =
            CertificateTestUtils.generateCertificate(payloadKeyPair, "XX", "Payload Cert", cscaCertificate,
                cscaPrivateKey);

        try {
            signerInformationService.deleteSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(
                SignerInformationService.SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED, e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }

    @Test
    void testDeleteFailedWrongSignerCertificate() throws Exception {
        long signerInformationEntitiesInDb = signerInformationRepository.count();

        X509Certificate signerCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.UPLOAD, "XX");

        X509Certificate cscaCertificate =
            trustedPartyTestHelper.getCert(TrustedPartyEntity.CertificateType.CSCA, countryCode);
        PrivateKey cscaPrivateKey =
            trustedPartyTestHelper.getPrivateKey(TrustedPartyEntity.CertificateType.CSCA, countryCode);

        KeyPair payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate payloadCertificate =
            CertificateTestUtils.generateCertificate(payloadKeyPair, countryCode, "Payload Cert", cscaCertificate,
                cscaPrivateKey);

        try {
            signerInformationService.deleteSignerCertificate(
                new X509CertificateHolder(payloadCertificate.getEncoded()),
                new X509CertificateHolder(signerCertificate.getEncoded()),
                countryCode
            );
        } catch (SignerInformationService.SignerCertCheckException e) {
            Assertions.assertEquals(SignerInformationService.SignerCertCheckException.Reason.UPLOADER_CERT_CHECK_FAILED,
                e.getReason());
        }

        Assertions.assertEquals(signerInformationEntitiesInDb, signerInformationRepository.count());
    }
}
