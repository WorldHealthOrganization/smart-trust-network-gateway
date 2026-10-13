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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.entity.FederationGatewayEntity;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.entity.TrustedPartyEntity;
import eu.europa.ec.dgc.gateway.repository.SignerInformationRepository;
import eu.europa.ec.dgc.gateway.restapi.dto.did.TrustedUploadDidDocumentDto;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.Objects;
import java.util.Optional;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class SignerInformationService {

    private final TrustedPartyService trustedPartyService;

    private final ThreatDetectionService threatDetectionService;

    private final CertificateUtils certificateUtils;

    private final SignerInformationRepository signerInformationRepository;

    private final DgcConfigProperties configProperties;

    private final ObjectMapper objectMapper;

    private static final String MDC_PROP_UPLOAD_CERT_THUMBPRINT = "uploadCertThumbprint";
    private static final String MDC_PROP_CSCA_CERT_THUMBPRINT = "cscaCertThumbprint";

    /**
     * Separator used by TNG to publish coded values of a verification method as DID fragment reference.
     */
    private static final String DID_FRAGMENT_SEPARATOR = "#";

    private static final String DEFAULT_DOMAIN = "DCC";

    /**
     * Maximum length of the {@code kid} column of {@link SignerInformationEntity}.
     */
    private static final int MAX_KID_LENGTH = 20;


    /**
     * Method to query persistence layer for SignerInformation filtered by Type = DSC.
     *
     * @return List of SignerInformation
     */
    public List<SignerInformationEntity> getNonFederatedEuDscSignerInformation() {
        return signerInformationRepository.getByCertificateTypeAndSourceGatewayIsNullAndDomainIs(
            SignerInformationEntity.CertificateType.DSC, "DCC");
    }

    /**
     * Method to query persistence layer for SignerInformation filtered by Type and Country.
     *
     * @param countryCode 2-digit country Code to filter for.
     * @param type        type to filter for
     * @return List of SignerInformation
     */
    public List<SignerInformationEntity> getNonFederatedSignerInformation(
        String countryCode,
        SignerInformationEntity.CertificateType type) {
        return signerInformationRepository.getByCertificateTypeAndCountryAndSourceGatewayIsNullAndDomainIs(type,
            countryCode, "DCC");
    }

    /**
     * Method to query persistence layer for all stored non federated SignerInformation matching given criteria.
     *
     * @return List of SignerInformation
     */
    public List<SignerInformationEntity> getSignerInformation(
        List<String> groups, List<String> country, List<String> domain, boolean withFederation) {

        final List<SignerInformationEntity.CertificateType> types = new ArrayList<>();
        if (groups != null) {
            groups.forEach(group -> {
                if (SignerInformationEntity.CertificateType.stringValues().contains(group)) {
                    types.add(SignerInformationEntity.CertificateType.valueOf(group));
                }
            });

            if (!groups.isEmpty() && types.isEmpty()) {
                /*
                  No group has matched --> All groups are invalid or user has searched for TrustedParty
                  -> Skipping Search for SignerInformation
                 */
                return Collections.emptyList();
            }
        }

        if (withFederation) {
            return signerInformationRepository.search(
                types, types.isEmpty(),
                country, country == null || country.isEmpty(),
                domain, domain == null || domain.isEmpty());
        } else {
            return signerInformationRepository.searchNonFederated(
                types, types.isEmpty(),
                country, country == null || country.isEmpty(),
                domain, domain == null || domain.isEmpty());
        }
    }

    /**
     * Adds a new Trusted Certificate to TrustStore DB.
     *
     * <p>If the same certificate was previously imported from a DID document by the same country, the CMS upload
     * supersedes it: the DID entry is removed and a new CMS entry is created.
     *
     * @param uploadedCertificate      the certificate to add
     * @param signerCertificate        the certificate which was used to sign the message
     * @param signature                the detached signature of cms message
     * @param authenticatedCountryCode the country code of the uploader country from cert authentication
     * @param kid                      Optional custom KID
     * @param group                    Group (Certificate Type)
     * @param domain                   Domain the certificate belongs to
     * @param properties               Map with custom properties assigned to the certificate
     * @return created Entity
     * @throws SignerCertCheckException if something went wrong
     */
    @Transactional(rollbackFor = SignerCertCheckException.class)
    public SignerInformationEntity addTrustedCertificate(
        X509CertificateHolder uploadedCertificate,
        X509CertificateHolder signerCertificate,
        String signature,
        String authenticatedCountryCode,
        String kid,
        String group,
        String domain,
        Map<String, String> properties
    ) throws SignerCertCheckException {
        contentCheckForThreats(uploadedCertificate);
        contentCheckUploaderCertificate(signerCertificate, authenticatedCountryCode);
        if (group == null || group.equals("DSC")) {
            contentCheckCountryOfOrigin(uploadedCertificate, authenticatedCountryCode);
        }
        if (Objects.isNull(group)) {
            group = "DSC";
        }
        contentCheckOneOf(group, SignerInformationEntity.CertificateType.stringValues());
        contentCheckOneOf(domain, configProperties.getTrustedCertificates().getAllowedDomains());
        for (String key : properties.keySet()) {
            contentCheckOneOf(key, configProperties.getTrustedCertificates().getAllowedProperties());
        }
        contentCheckCsca(uploadedCertificate, authenticatedCountryCode, group);
        final Optional<SignerInformationEntity> supersededDidEntity =
            resolveSupersededDidEntity(uploadedCertificate, authenticatedCountryCode);
        contentCheckKidAlreadyExists(uploadedCertificate, kid);

        // All checks passed --> Save to DB
        byte[] certRawData;
        try {
            certRawData = uploadedCertificate.getEncoded();
        } catch (IOException e) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOAD_FAILED, "Internal Server Error");
        }

        SignerInformationEntity newSignerInformation = new SignerInformationEntity();
        newSignerInformation.setCountry(authenticatedCountryCode);
        newSignerInformation.setRawData(Base64.getEncoder().encodeToString(certRawData));
        newSignerInformation.setThumbprint(certificateUtils.getCertThumbprint(uploadedCertificate));
        newSignerInformation.setCertificateType(
                SignerInformationEntity.CertificateType.valueOf(group) == SignerInformationEntity.CertificateType.DESC
                ? SignerInformationEntity.CertificateType.DESC : SignerInformationEntity.CertificateType.DSC);
        newSignerInformation.setSignature(signature);
        newSignerInformation.setKid(kid);
        newSignerInformation.setDomain(domain == null ? "DCC" : domain);
        if (!properties.isEmpty()) {
            try {
                newSignerInformation.setProperties(objectMapper.writeValueAsString(properties));
            } catch (JsonProcessingException e) {
                throw new SignerCertCheckException(SignerCertCheckException.Reason.PROPERTY_SERIALIZATION_FAILED,
                    "Failed to serialize properties.");
            }
        }

        if (supersededDidEntity.isPresent()) {
            log.info("Removing existing DID SignerInformation Entity {} to replace it with CMS upload",
                supersededDidEntity.get().getId());
            signerInformationRepository.delete(supersededDidEntity.get());
            // Hibernate executes inserts before deletes, which would violate the unique thumbprint constraint
            signerInformationRepository.flush();
        }

        log.info("Saving new SignerInformation Entity");

        newSignerInformation = signerInformationRepository.save(newSignerInformation);

        DgcMdc.remove(MDC_PROP_UPLOAD_CERT_THUMBPRINT);
        DgcMdc.remove(MDC_PROP_CSCA_CERT_THUMBPRINT);

        return newSignerInformation;
    }

    /**
     * Update a CMS package.
     *
     * @param id                       The entity to update
     * @param uploadedCertificate      the certificate to add
     * @param signerCertificate        the certificate which was used to sign the message
     * @param signature                the detached signature of cms message
     * @param authenticatedCountryCode the country code of the uploader country from cert authentication
     * @throws SignerCertCheckException if validation check has failed. The exception contains
     *                                  a reason property with detailed information why the validation has failed.
     */
    public SignerInformationEntity updateSignerCertificate(
        Long id,
        X509CertificateHolder uploadedCertificate,
        X509CertificateHolder signerCertificate,
        String signature,
        String authenticatedCountryCode
    ) throws SignerCertCheckException {

        final SignerInformationEntity signerInformationEntity = signerInformationRepository.findById(id).orElseThrow(
            () -> new SignerCertCheckException(SignerCertCheckException.Reason.EXIST_CHECK_FAILED,
                "Uploaded certificate does not exists"));

        String signerCertificateType = Optional.ofNullable(
                signerInformationEntity.getCertificateType())
                .map(Enum::toString)
                .orElse(SignerInformationEntity.CertificateType.DSC.toString());
        contentCheckUploaderCertificate(signerCertificate, authenticatedCountryCode);
        contentCheckCountryOfOrigin(uploadedCertificate, authenticatedCountryCode);
        contentCheckCsca(uploadedCertificate, authenticatedCountryCode, signerCertificateType);

        byte[] certRawData;
        try {
            certRawData = uploadedCertificate.getEncoded();
        } catch (IOException e) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOAD_FAILED, "Internal Server Error");
        }

        signerInformationEntity.setRawData(Base64.getEncoder().encodeToString(certRawData));
        signerInformationEntity.setThumbprint(certificateUtils.getCertThumbprint(uploadedCertificate));
        signerInformationEntity.setCertificateType(
                SignerInformationEntity.CertificateType.valueOf(signerCertificateType));
        signerInformationEntity.setSignature(signature);

        log.info("Updating SignerInformation Entity");

        SignerInformationEntity updatedEntity = signerInformationRepository.save(signerInformationEntity);

        DgcMdc.remove(MDC_PROP_UPLOAD_CERT_THUMBPRINT);
        DgcMdc.remove(MDC_PROP_CSCA_CERT_THUMBPRINT);

        return updatedEntity;
    }

    /**
     * Adds a new Trusted Signer Certificate to TrustStore DB.
     *
     * @param uploadedCertificate      the certificate to add
     * @param signerCertificate        the certificate which was used to sign the message
     * @param signature                the detached signature of cms message
     * @param authenticatedCountryCode the country code of the uploader country from cert authentication
     * @throws SignerCertCheckException if validation check has failed. The exception contains
     *                                  a reason property with detailed information why the validation has failed.
     */
    @Transactional(rollbackFor = SignerCertCheckException.class)
    public SignerInformationEntity addSignerCertificate(
        X509CertificateHolder uploadedCertificate,
        X509CertificateHolder signerCertificate,
        String signature,
        String authenticatedCountryCode
    ) throws SignerCertCheckException {

        return addTrustedCertificate(
            uploadedCertificate,
            signerCertificate,
            signature,
            authenticatedCountryCode,
            null,
            null,
            null,
            Collections.emptyMap());
    }

    /**
     * Adds the certificates of a successfully verified uploaded DID document to the TrustStore DB.
     *
     * <p>A DID document may contain any number of verification methods, each carrying its own JWK. Per
     * RFC 7517 section 4.7 the first entry of the {@code x5c} property is the certificate containing the key of the
     * JWK, all further entries form its certificate chain (e.g. the CSCA). Therefore exactly one entry is created per
     * verification method, based on {@code x5c[0]}. The country is taken from the participant code of the
     * verification method, the signer certificate is the upload certificate (UP.pem) of that participant and the
     * signature is the Base64 encoded representation of the uploaded DID document.
     *
     * @param didDocument the verified DID document to persist
     * @return the created or replaced entities, one per distinct certificate
     * @throws SignerCertCheckException if validation check has failed. The exception contains
     *                                  a reason property with detailed information why the validation has failed.
     */
    @Transactional(rollbackFor = SignerCertCheckException.class)
    public List<SignerInformationEntity> addDidSignerCertificates(TrustedUploadDidDocumentDto didDocument)
        throws SignerCertCheckException {

        String signature = encodeDidDocumentAsSignature(didDocument);
        Map<String, SignerInformationEntity> storedEntities = new LinkedHashMap<>();

        for (TrustedUploadDidDocumentDto.VerificationMethod verificationMethod : didDocument.getVerificationMethod()) {
            String countryCode = resolveParticipantCountryCode(verificationMethod);
            String domain = resolveDomain(verificationMethod);
            String keyUsage = resolveKeyUsage(verificationMethod);
            X509CertificateHolder signerCertificate = getUploadCertificate(countryCode);

            TrustedUploadDidDocumentDto.PublicKeyJwk publicKeyJwk = verificationMethod.getPublicKeyJwk();
            String encodedCertificate = publicKeyJwk.getEncodedX509Certificates().get(0);
            X509CertificateHolder keyCertificate = parseCertificate(encodedCertificate);

            contentCheckDidKeyCertificate(keyCertificate, publicKeyJwk, verificationMethod.getId());

            String thumbprint = certificateUtils.getCertThumbprint(keyCertificate);
            if (storedEntities.containsKey(thumbprint)) {
                log.info("Skipping verification method {}: certificate {} already imported from this document",
                    verificationMethod.getId(), thumbprint);
                continue;
            }

            String kid = resolveKid(verificationMethod);

            storedEntities.put(thumbprint,
                addDidSignerCertificate(encodedCertificate, keyCertificate, signerCertificate, signature,
                    countryCode, domain, keyUsage, kid));
        }

        return new ArrayList<>(storedEntities.values());
    }

    /**
     * Deletes all entries imported from uploaded DID documents for the given domain, participant and key usage.
     *
     * <p>All coded values may be provided with or without DID fragment prefix (e.g. {@code #DCC} or {@code DCC}).
     * The participant may be an ISO 3166 Alpha-2 or Alpha-3 code. Every entry of the given domain and country
     * whose stored DID document contains a verification method matching the requested domain and key usage is
     * removed.
     *
     * @param domain      the domain, e.g. {@code DCC}
     * @param participant the participant code, e.g. {@code DE} or {@code DEU}
     * @param keyUsage    the key usage, e.g. {@code DSC} or {@code CSCA}
     * @return the number of deleted entries
     * @throws SignerCertCheckException if the participant code is not a valid country code
     */
    @Transactional(rollbackFor = SignerCertCheckException.class)
    public int deleteDidSignerCertificates(String domain, String participant, String keyUsage)
        throws SignerCertCheckException {

        String normalizedDomain = normalizeCode(domain);
        String normalizedKeyUsage = normalizeCode(keyUsage);
        String countryCode = normalizeParticipantCountryCode(participant);

        List<SignerInformationEntity> entitiesToDelete = signerInformationRepository
            .getBySourceTypeAndDomainAndCountryAndSourceGatewayIsNullOrderByCreatedAtDesc(
                SignerInformationEntity.SourceType.DID, normalizedDomain, countryCode)
            .stream()
            .filter(entity -> entity.getSignature() != null)
            .filter(entity -> {
                String didDocument = decodeDidDocument(entity.getSignature());
                return didDocument != null
                    && containsVerificationMethod(didDocument, normalizedDomain, normalizedKeyUsage);
            })
            .toList();

        entitiesToDelete.forEach(entity -> log.info(
            "Deleting DID SignerInformation Entity {} (domain={}, country={}, keyusage={})",
            entity.getId(), normalizedDomain, countryCode, normalizedKeyUsage));

        signerInformationRepository.deleteAll(entitiesToDelete);

        return entitiesToDelete.size();
    }

    private String decodeDidDocument(String signature) {
        try {
            return new String(Base64.getDecoder().decode(signature), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            log.warn("Failed to decode stored DID document: {}", e.getMessage());
            return null;
        }
    }

    private boolean containsVerificationMethod(String didDocument, String domain, String keyUsage) {
        try {
            TrustedUploadDidDocumentDto document =
                objectMapper.readValue(didDocument, TrustedUploadDidDocumentDto.class);

            if (document.getVerificationMethod() == null) {
                return false;
            }

            return document.getVerificationMethod().stream().anyMatch(verificationMethod -> {
                String methodDomain = resolveDomain(verificationMethod);
                return keyUsage.equals(resolveKeyUsage(verificationMethod))
                    && domain.equals(methodDomain != null ? methodDomain : DEFAULT_DOMAIN);
            });
        } catch (JsonProcessingException e) {
            log.warn("Failed to parse stored DID document: {}", e.getMessage());
            return false;
        }
    }

    private String normalizeCode(String code) {
        String strippedCode = stripDidFragmentPrefix(code);
        return strippedCode == null ? "" : strippedCode.toUpperCase(Locale.ROOT);
    }

    /**
     * Normalizes a DID participant to its Alpha-2 country, including fragment prefixes and virtual countries.
     *
     * @param participant the Alpha-2 or Alpha-3 participant code
     * @return the normalized Alpha-2 country code
     * @throws SignerCertCheckException if the participant cannot be mapped to a country code
     */
    public String normalizeParticipantCountryCode(String participant) throws SignerCertCheckException {
        return toAlpha2CountryCode(normalizeCode(participant));
    }

    private String toAlpha2CountryCode(String participantCode) throws SignerCertCheckException {
        if (participantCode.length() == 2) {
            return participantCode;
        } else if (participantCode.length() == 3) {
            return convertAlpha3ToAlpha2(participantCode);
        }

        throw new SignerCertCheckException(SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED,
            "Participant code %s is not a valid country code.", participantCode);
    }

    /**
     * Ensures {@code x5c[0]} is an end-entity certificate holding exactly the public key of the JWK.
     *
     * <p>Coordinates are compared as unsigned integers because some publishers encode them with a leading
     * {@code 0x00} sign byte (e.g. {@code "AMj6..."}), which is the same key.
     */
    private void contentCheckDidKeyCertificate(X509CertificateHolder keyCertificate,
                                               TrustedUploadDidDocumentDto.PublicKeyJwk publicKeyJwk,
                                               String verificationMethodId) throws SignerCertCheckException {

        X509Certificate certificate;
        try {
            certificate = new JcaX509CertificateConverter().getCertificate(keyCertificate);
        } catch (CertificateException e) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOAD_FAILED,
                "Failed to parse x5c[0] of verification method %s: %s", verificationMethodId, e.getMessage());
        }

        if (certificate.getBasicConstraints() >= 0) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOAD_FAILED,
                "x5c[0] of verification method %s is a CA certificate, expected the certificate of the JWK key.",
                verificationMethodId);
        }

        boolean matches;
        if (publicKeyJwk instanceof TrustedUploadDidDocumentDto.EcPublicKeyJwk ecJwk
            && certificate.getPublicKey() instanceof ECPublicKey ecPublicKey) {
            matches = ecPublicKey.getW().getAffineX().equals(decodeUnsignedBase64Url(ecJwk.getValueX()))
                && ecPublicKey.getW().getAffineY().equals(decodeUnsignedBase64Url(ecJwk.getValueY()));
        } else if (publicKeyJwk instanceof TrustedUploadDidDocumentDto.RsaPublicKeyJwk rsaJwk
            && certificate.getPublicKey() instanceof RSAPublicKey rsaPublicKey) {
            matches = rsaPublicKey.getModulus().equals(decodeUnsignedBase64Url(rsaJwk.getValueN()))
                && rsaPublicKey.getPublicExponent().equals(decodeUnsignedBase64Url(rsaJwk.getValueE()));
        } else {
            matches = false;
        }

        if (!matches) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOAD_FAILED,
                "Public key of x5c[0] does not match the JWK of verification method %s.", verificationMethodId);
        }
    }

    private BigInteger decodeUnsignedBase64Url(String value) throws SignerCertCheckException {
        try {
            return new BigInteger(1, Base64.getUrlDecoder().decode(value));
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOAD_FAILED,
                "JWK contains an invalid key parameter.");
        }
    }

    private SignerInformationEntity addDidSignerCertificate(
        String encodedCertificate,
        X509CertificateHolder uploadedCertificate,
        X509CertificateHolder signerCertificate,
        String signature,
        String countryCode,
        String domain,
        String keyUsage,
        String kid
    ) throws SignerCertCheckException {

        String thumbprint = certificateUtils.getCertThumbprint(uploadedCertificate);

        contentCheckForThreats(uploadedCertificate);
        contentCheckUploaderCertificate(signerCertificate, countryCode);

        SignerInformationEntity signerInformation = resolveDidTargetEntity(thumbprint, countryCode);

        contentCheckDidKidAlreadyExists(thumbprint, kid);

        signerInformation.setCreatedAt(ZonedDateTime.now());
        signerInformation.setCountry(countryCode);
        signerInformation.setRawData(encodedCertificate);
        signerInformation.setThumbprint(thumbprint);
        signerInformation.setCertificateType(SignerInformationEntity.CertificateType.DSC);
        signerInformation.setSignature(signature);
        signerInformation.setSourceType(SignerInformationEntity.SourceType.DID);
        signerInformation.setDomain(domain != null ? domain : DEFAULT_DOMAIN);
        signerInformation.setKid(kid);
        signerInformation.setProperties(null);
        signerInformation.setSourceGateway(null);

        log.info("Saving SignerInformation Entity imported from DID document "
                + "(domain={}, keyusage={}, kid={}, version={})",
            signerInformation.getDomain(), keyUsage, kid, signerInformation.getVersion());

        SignerInformationEntity savedEntity = signerInformationRepository.save(signerInformation);

        DgcMdc.remove(MDC_PROP_UPLOAD_CERT_THUMBPRINT);

        return savedEntity;
    }

    /**
     * Extracts the KID of a verification method from the {@code kid} property of its {@code publicKeyJwk}.
     *
     * @param verificationMethod the verification method
     * @return the KID or {@code null} if the JWK does not contain a {@code kid}
     * @throws SignerCertCheckException if the KID exceeds the maximum length of the KID column
     */
    private String resolveKid(TrustedUploadDidDocumentDto.VerificationMethod verificationMethod)
        throws SignerCertCheckException {

        TrustedUploadDidDocumentDto.PublicKeyJwk publicKeyJwk = verificationMethod.getPublicKeyJwk();
        String kid = publicKeyJwk == null || publicKeyJwk.getKeyId() == null
            ? null : publicKeyJwk.getKeyId().trim();

        if (kid == null || kid.isEmpty()) {
            return null;
        }

        if (kid.length() > MAX_KID_LENGTH) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.KID_CHECK_FAILED,
                "KID %s of verification method %s exceeds the maximum length of %d characters.",
                kid, verificationMethod.getId(), MAX_KID_LENGTH);
        }

        return kid;
    }

    /**
     * Ensures the KID of a certificate imported from a DID document is not used by any other certificate.
     *
     * <p>The entity with the same thumbprint is excluded, as it is replaced by the DID import.
     *
     * @param thumbprint the thumbprint of the imported certificate
     * @param kid        the KID taken from the verification method, may be {@code null}
     */
    private void contentCheckDidKidAlreadyExists(String thumbprint, String kid) throws SignerCertCheckException {

        String effectiveKid = kid != null ? kid : thumbprint.substring(0, 16);

        if (signerInformationRepository.getFirstByThumbprintStartsWithAndThumbprintIsNot(effectiveKid, thumbprint)
            .isPresent()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.KID_CHECK_FAILED,
                "A certificate with KID %s already exists", effectiveKid);
        }

        Optional<SignerInformationEntity> kidOwner = signerInformationRepository.getFirstByKid(effectiveKid);

        if (kidOwner.isPresent() && !thumbprint.equals(kidOwner.get().getThumbprint())) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.KID_CHECK_FAILED,
                "A certificate with KID %s already exists", effectiveKid);
        }
    }

    /**
     * Determines the entity a certificate imported from a DID document is written to.
     *
     * <ul>
     *     <li>No entry with the thumbprint exists: a new entity is created.</li>
     *     <li>An entry imported from a DID document exists: it is replaced in place and its version is increased.</li>
     *     <li>An entry of any other source (e.g. CMS) exists: it is removed and a new DID entity is created.</li>
     * </ul>
     *
     * @param thumbprint the thumbprint of the uploaded certificate
     * @param countryCode the country authorized to upload the certificate
     * @return the entity to populate and save
     */
    private SignerInformationEntity resolveDidTargetEntity(String thumbprint, String countryCode)
            throws SignerCertCheckException {

        Optional<SignerInformationEntity> existingEntity = signerInformationRepository.getFirstByThumbprint(thumbprint);

        if (existingEntity.isEmpty()) {
            return new SignerInformationEntity();
        }

        SignerInformationEntity existing = existingEntity.get();

        if (!countryCode.equals(existing.getCountry())) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED,
                "Cannot replace a certificate belonging to country %s.", existing.getCountry());
        }

        if (existing.getSourceType() == SignerInformationEntity.SourceType.DID) {
            existing.setVersion(existing.getVersion() == null ? 1 : existing.getVersion() + 1);
            log.info("Replacing existing DID SignerInformation Entity {} (new version {})",
                existing.getId(), existing.getVersion());
            return existing;
        }

        log.info("Removing existing {} SignerInformation Entity {} to replace it with DID import",
            existing.getSourceType(), existing.getId());

        signerInformationRepository.delete(existing);
        // Hibernate executes inserts before deletes, which would violate the unique thumbprint constraint
        signerInformationRepository.flush();

        return new SignerInformationEntity();
    }

    private String encodeDidDocumentAsSignature(TrustedUploadDidDocumentDto didDocument)
        throws SignerCertCheckException {

        try {
            return Base64.getEncoder().encodeToString(
                objectMapper.writeValueAsString(didDocument).getBytes(StandardCharsets.UTF_8));
        } catch (JsonProcessingException e) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOAD_FAILED,
                "Failed to serialize uploaded DID document.");
        }
    }

    private X509CertificateHolder parseCertificate(String encodedCertificate) throws SignerCertCheckException {
        try {
            return new X509CertificateHolder(Base64.getDecoder().decode(encodedCertificate));
        } catch (IOException | IllegalArgumentException e) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOAD_FAILED,
                "Failed to parse certificate of x5c property: %s", e.getMessage());
        }
    }

    private X509CertificateHolder getUploadCertificate(String countryCode) throws SignerCertCheckException {
        return trustedPartyService.getCertificate(countryCode, TrustedPartyEntity.CertificateType.UPLOAD).stream()
            .map(trustedPartyService::getX509CertificateHolderFromEntity)
            .filter(Objects::nonNull)
            .findFirst()
            .orElseThrow(() -> new SignerCertCheckException(
                SignerCertCheckException.Reason.UPLOADER_CERT_CHECK_FAILED,
                "Could not find upload certificate for country %s", countryCode));
    }

    private String resolveParticipantCountryCode(TrustedUploadDidDocumentDto.VerificationMethod verificationMethod)
        throws SignerCertCheckException {

        String participantCode = stripDidFragmentPrefix(verificationMethod.getParticipant() == null
            ? null : verificationMethod.getParticipant().getCode());

        if (participantCode == null || participantCode.isBlank()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED,
                "Verification method %s does not contain a participant code.", verificationMethod.getId());
        }

        return normalizeParticipantCountryCode(participantCode);
    }

    /**
     * Resolves the domain of a verification method, e.g. {@code "#DCC"} becomes {@code "DCC"}.
     *
     * @return the domain without DID fragment prefix or {@code null} if the verification method does not define one
     */
    private String resolveDomain(TrustedUploadDidDocumentDto.VerificationMethod verificationMethod) {

        String domain = stripDidFragmentPrefix(verificationMethod.getDomain() == null
            ? null : verificationMethod.getDomain().getCode());

        return domain == null || domain.isBlank() ? null : domain.toUpperCase(Locale.ROOT);
    }

    /**
     * Resolves the key usage of a verification method, e.g. {@code "#CSCA"} becomes {@code "CSCA"}.
     *
     * @return the key usage without DID fragment prefix or {@code null} if the verification method does not define one
     */
    private String resolveKeyUsage(TrustedUploadDidDocumentDto.VerificationMethod verificationMethod) {

        String keyUsage = stripDidFragmentPrefix(verificationMethod.getKeyUsage() == null
            ? null : verificationMethod.getKeyUsage().getCode());

        return keyUsage == null || keyUsage.isBlank() ? null : keyUsage.toUpperCase(Locale.ROOT);
    }

    /**
     * Removes the leading DID fragment separator from a coded value.
     *
     * <p>TNG publishes the {@code domain}, {@code participant} and {@code keyusage} codes of a verification
     * method as DID fragment references, e.g. {@code "#DCC"}, {@code "#AND"} or {@code "#CSCA"}. Only the plain
     * code must be persisted.
     *
     * @param code the coded value as contained in the DID document, may be {@code null}
     * @return the code without leading {@code #}, or {@code null} if the input was {@code null}
     */
    private String stripDidFragmentPrefix(String code) {

        if (code == null) {
            return null;
        }

        String strippedCode = code.trim();

        return strippedCode.startsWith(DID_FRAGMENT_SEPARATOR) ? strippedCode.substring(1) : strippedCode;
    }

    private String convertAlpha3ToAlpha2(String alpha3) throws SignerCertCheckException {
        Optional<String> virtualCountry = configProperties.getCountryCodeMap().getVirtualCountries().entrySet().stream()
            .filter(entry -> alpha3.equalsIgnoreCase(entry.getValue()))
            .map(Map.Entry::getKey)
            .findFirst();

        if (virtualCountry.isPresent()) {
            return virtualCountry.get().toUpperCase(Locale.ROOT);
        }

        return Arrays.stream(Locale.getISOCountries())
            .filter(alpha2 -> alpha3.equalsIgnoreCase(getIso3Country(alpha2)))
            .findFirst()
            .orElseThrow(() -> new SignerCertCheckException(
                SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED,
                "Participant code %s could not be mapped to an ISO 3166 Alpha-2 country code.", alpha3));
    }

    private String getIso3Country(String alpha2) {
        try {
            return new Locale("en", alpha2).getISO3Country();
        } catch (MissingResourceException e) {
            return null;
        }
    }

    /**
     * Insert a new federated Signer Certificate.
     *
     * @param base64EncodedCertificate Base64 encoded Certificate
     * @param signature                Upload Certificate Signature
     * @param countryCode              Country Code of uploaded certificate
     * @param kid                      KID of the certificate
     * @param sourceGateway            Gateway the cert is originated from
     * @return persisted Entity
     * @throws SignerCertCheckException if insert failed.
     */
    public SignerInformationEntity addFederatedSignerCertificate(
        String base64EncodedCertificate,
        String signature,
        String countryCode,
        String kid,
        String domain,
        String uuid,
        Integer version,
        FederationGatewayEntity sourceGateway
    ) throws SignerCertCheckException {

        X509CertificateHolder certificate;
        try {
            certificate = new X509CertificateHolder(
                Base64.getDecoder().decode(base64EncodedCertificate)
            );
        } catch (IOException e) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOAD_FAILED,
                "Failed to decode Raw Cert");
        }

        contentCheckAlreadyExists(certificate);

        SignerInformationEntity newSignerInformation = new SignerInformationEntity();
        newSignerInformation.setSourceGateway(sourceGateway);
        newSignerInformation.setKid(kid);
        newSignerInformation.setCountry(countryCode);
        newSignerInformation.setRawData(base64EncodedCertificate);
        newSignerInformation.setThumbprint(certificateUtils.getCertThumbprint(certificate));
        newSignerInformation.setCertificateType(SignerInformationEntity.CertificateType.DSC);
        newSignerInformation.setSignature(signature);

        if (uuid != null) {
            newSignerInformation.setUuid(uuid);
        }
        if (version != null) {
            newSignerInformation.setVersion(version);
        }
        newSignerInformation.setDomain(domain == null ? "DCC" : domain);

        log.info("Saving Federated SignerInformation Entity");

        return signerInformationRepository.save(newSignerInformation);
    }

    /**
     * Deletes a Trusted Signer Certificate from TrustStore DB.
     *
     * @param uploadedCertificate      the certificate to delete
     * @param signerCertificate        the certificate which was used to sign the message
     * @param authenticatedCountryCode the country code of the uploader country from cert authentication
     * @throws SignerCertCheckException if validation check has failed. The exception contains
     *                                  a reason property with detailed information why the validation has failed.
     */
    public void deleteSignerCertificate(
        X509CertificateHolder uploadedCertificate,
        X509CertificateHolder signerCertificate,
        String authenticatedCountryCode
    ) throws SignerCertCheckException {

        contentCheckUploaderCertificate(signerCertificate, authenticatedCountryCode);
        contentCheckCountryOfOrigin(uploadedCertificate, authenticatedCountryCode);
        contentCheckExists(uploadedCertificate);

        log.info("Revoking SignerInformation Entity");

        // All checks passed --> Delete from DB
        signerInformationRepository.deleteByThumbprint(certificateUtils.getCertThumbprint(uploadedCertificate));

        DgcMdc.remove(MDC_PROP_UPLOAD_CERT_THUMBPRINT);
    }

    /**
     * Deletes SignerCertificates by given GatewayId.
     *
     * @param gatewayId GatewayID of the certificates to delete.
     */
    public void deleteSignerCertificateByFederationGateway(String gatewayId) {
        log.info("Deleting SignerInformation by GatewayId {}", gatewayId);

        Long deleteCount = signerInformationRepository.deleteBySourceGatewayGatewayId(gatewayId);

        log.info("Deleted {} SignerInformation with GatewayId {}", deleteCount, gatewayId);
    }

    /**
     * Extracts X509Certificate from {@link SignerInformationEntity}.
     *
     * @param signerInformationEntity entity from which the certificate should be extracted.
     * @return X509Certificate representation.
     */
    public X509Certificate getX509CertificateFromEntity(SignerInformationEntity signerInformationEntity) {
        try {
            byte[] rawDataBytes = Base64.getDecoder().decode(signerInformationEntity.getRawData());
            return certificateUtils.convertCertificate(new X509CertificateHolder(rawDataBytes));
        } catch (Exception e) {
            log.error("Failed to parse Certificate from SignerInformationEntity", e);
        }

        return null;
    }

    private void contentCheckOneOf(String value, List<String> allowedValues) throws SignerCertCheckException {
        if (value == null) {
            return;
        }

        if (allowedValues.stream().noneMatch(value::equals)) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.PROPERTY_NOT_ALLOWED,
                String.format("Property Key or Value %s is not allowed. Allowed Values are: %s",
                    value, String.join(", ", allowedValues)));
        }
    }

    private void contentCheckForThreats(X509CertificateHolder certificate) throws SignerCertCheckException {
        String sub = certificate.getSubject().toString();
        String iss = certificate.getIssuer().toString();
        if (threatDetectionService.containsThreat(sub + iss)) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.THREAT_DETECTED,
                "Threat detected in certificate");
        }
    }

    private void contentCheckUploaderCertificate(
        X509CertificateHolder signerCertificate,
        String authenticatedCountryCode) throws SignerCertCheckException {
        // Content Check Step 1: Uploader Certificate
        String signerCertThumbprint = certificateUtils.getCertThumbprint(signerCertificate);
        Optional<TrustedPartyEntity> certFromDb = trustedPartyService.getCertificate(
            signerCertThumbprint,
            authenticatedCountryCode,
            TrustedPartyEntity.CertificateType.UPLOAD
        );

        if (certFromDb.isEmpty()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.UPLOADER_CERT_CHECK_FAILED,
                "Could not find upload certificate with hash %s and country %s",
                signerCertThumbprint, authenticatedCountryCode);
        }

        DgcMdc.put(MDC_PROP_UPLOAD_CERT_THUMBPRINT, signerCertThumbprint);
    }

    private void contentCheckCountryOfOrigin(X509CertificateHolder uploadedCertificate,
                                             String authenticatedCountryCode) throws SignerCertCheckException {

        // Content Check Step 2: Country of Origin check
        RDN[] uploadedCertCountryProperties =
            uploadedCertificate.getSubject().getRDNs(X509ObjectIdentifiers.countryName);

        if (uploadedCertCountryProperties.length > 1) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED,
                "Uploaded certificate contains more than one country property.");
        } else if (uploadedCertCountryProperties.length < 1) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED,
                "Uploaded certificate contains no country property.");
        }

        if (!uploadedCertCountryProperties[0].getFirst().getValue().toString().equals(authenticatedCountryCode)) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.COUNTRY_OF_ORIGIN_CHECK_FAILED,
                "Uploaded certificate is not issued for uploader country.");
        }
    }

    private void contentCheckCsca(X509CertificateHolder uploadedCertificate,
                                  String authenticatedCountryCode, String group) throws SignerCertCheckException {

        // Content Check Step 3: CSCA Check
        List<TrustedPartyEntity> trustedCas =
            trustedPartyService.getCertificate(authenticatedCountryCode,
                    SignerInformationEntity.CertificateType.valueOf(group)
                            == SignerInformationEntity.CertificateType.DESC
                            ? TrustedPartyEntity.CertificateType.DECA : TrustedPartyEntity.CertificateType.CSCA);

        if (trustedCas.isEmpty()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.CSCA_CHECK_FAILED,
                "CSCA list for country %s is empty", authenticatedCountryCode);
        }

        Optional<TrustedPartyEntity> matchingCa = trustedCas.stream()
            .dropWhile(ca -> !certificateSignedByCa(uploadedCertificate, ca))
            .findFirst();

        if (matchingCa.isEmpty()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.CSCA_CHECK_FAILED,
                "Could not verify uploaded certificate was signed by valid CSCA.");
        } else {
            DgcMdc.put(MDC_PROP_CSCA_CERT_THUMBPRINT, matchingCa.get().getThumbprint());
        }
    }

    private void contentCheckAlreadyExists(X509CertificateHolder uploadedCertificate) throws SignerCertCheckException {

        String uploadedCertificateThumbprint = certificateUtils.getCertThumbprint(uploadedCertificate);
        Optional<SignerInformationEntity> signerInformationEntity =
            signerInformationRepository.getFirstByThumbprint(uploadedCertificateThumbprint);

        if (signerInformationEntity.isPresent()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.ALREADY_EXIST_CHECK_FAILED,
                "Uploaded certificate already exists");
        }
    }

    /**
     * Checks whether the uploaded certificate conflicts with an existing entry.
     *
     * <p>An entry imported from a DID document by the same country is superseded by the CMS upload and returned
     * so it can be replaced. Any other existing entry (CMS, federated or owned by another country) is a conflict.
     *
     * @return the DID entry to replace or empty if the certificate does not exist yet
     */
    private Optional<SignerInformationEntity> resolveSupersededDidEntity(
        X509CertificateHolder uploadedCertificate, String authenticatedCountryCode) throws SignerCertCheckException {

        Optional<SignerInformationEntity> existingEntity =
            signerInformationRepository.getFirstByThumbprint(certificateUtils.getCertThumbprint(uploadedCertificate));

        if (existingEntity.isEmpty()) {
            return Optional.empty();
        }

        SignerInformationEntity existing = existingEntity.get();
        if (existing.getSourceType() == SignerInformationEntity.SourceType.DID
            && existing.getSourceGateway() == null
            && authenticatedCountryCode.equals(existing.getCountry())) {
            return existingEntity;
        }

        throw new SignerCertCheckException(SignerCertCheckException.Reason.ALREADY_EXIST_CHECK_FAILED,
            "Uploaded certificate already exists");
    }

    private void contentCheckKidAlreadyExists(X509CertificateHolder uploadedCertificate, String customKid)
        throws SignerCertCheckException {
        String uploadedCertificateThumbprint = certificateUtils.getCertThumbprint(uploadedCertificate);
        String kid = customKid;
        if (customKid == null) {
            // Custom Kid not provided, using the first 8 byte of hash as fallback.
            kid = uploadedCertificateThumbprint.substring(0, 16);
        }

        Optional<SignerInformationEntity> signerInformationEntity = signerInformationRepository
            .getFirstByThumbprintStartsWithAndThumbprintIsNot(kid, uploadedCertificateThumbprint);

        if (signerInformationEntity.isPresent()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.KID_CHECK_FAILED,
                "A certificate with KID of uploaded certificate already exists");
        }

        signerInformationEntity = signerInformationRepository.getFirstByKid(kid);

        // An entry of the same certificate is a superseded DID entry, which is replaced by this upload
        if (signerInformationEntity.isPresent()
            && !uploadedCertificateThumbprint.equals(signerInformationEntity.get().getThumbprint())) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.KID_CHECK_FAILED,
                "A certificate with KID of uploaded certificate already exists");
        }
    }

    private void contentCheckExists(X509CertificateHolder uploadedCertificate) throws SignerCertCheckException {

        String uploadedCertificateThumbprint = certificateUtils.getCertThumbprint(uploadedCertificate);
        Optional<SignerInformationEntity> signerInformationEntity =
            signerInformationRepository.getFirstByThumbprint(uploadedCertificateThumbprint);

        if (signerInformationEntity.isEmpty()) {
            throw new SignerCertCheckException(SignerCertCheckException.Reason.EXIST_CHECK_FAILED,
                "Uploaded certificate does not exists");
        }
    }

    private boolean certificateSignedByCa(X509CertificateHolder certificate, TrustedPartyEntity caCertificateEntity) {
        X509Certificate caCertificate = trustedPartyService.getX509CertificateFromEntity(caCertificateEntity);

        ContentVerifierProvider verifier;
        try {
            verifier = new JcaContentVerifierProviderBuilder().build(caCertificate);
        } catch (OperatorCreationException e) {
            DgcMdc.put("certHash", caCertificateEntity.getThumbprint());
            log.error("Failed to instantiate JcaContentVerifierProvider from cert");
            return false;
        }

        try {
            return certificate.isSignatureValid(verifier);
        } catch (CertException | RuntimeOperatorException e) {
            return false;
        }
    }

    public static class SignerCertCheckException extends Exception {

        @Getter
        private final Reason reason;

        public SignerCertCheckException(Reason reason, String message, Object... args) {
            super(String.format(message, args));
            this.reason = reason;
        }

        public enum Reason {
            UPLOADER_CERT_CHECK_FAILED,
            COUNTRY_OF_ORIGIN_CHECK_FAILED,
            CSCA_CHECK_FAILED,
            ALREADY_EXIST_CHECK_FAILED,
            KID_CHECK_FAILED,
            EXIST_CHECK_FAILED,
            UPLOAD_FAILED,
            PROPERTY_NOT_ALLOWED,
            PROPERTY_SERIALIZATION_FAILED,
            THREAT_DETECTED
        }
    }
}
