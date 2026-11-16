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

import com.apicatalog.jsonld.loader.DocumentLoader;
import eu.europa.ec.dgc.did.DidVerificationService;
import eu.europa.ec.dgc.gateway.testdata.DidTestHelper;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Slf4j
class DidVerificationServiceTest {

    @Autowired
    DidVerificationService didVerificationService;

    @Autowired
    DocumentLoader didContextLoader;

    @Test
    void shouldVerifyProofOfCorrectlySignedDidDocument() throws Exception {
        KeyPair keyPair = DidTestHelper.generateEcKeyPair();
        String signedDidDocument = signDidDocument(keyPair);

        boolean verified = didVerificationService.verify(signedDidDocument, keyPair.getPublic());
        log.info("Verification result for correctly signed DID document: {}", verified);

        Assertions.assertTrue(verified,
                "Proof of a correctly signed DID document should be verified successfully.");
    }

    @Test
    void shouldNotVerifyProofWithNonMatchingPublicKey() throws Exception {
        KeyPair signingKeyPair = DidTestHelper.generateEcKeyPair();
        KeyPair otherKeyPair = DidTestHelper.generateEcKeyPair();

        String signedDidDocument = signDidDocument(signingKeyPair);

        boolean verified = didVerificationService.verify(signedDidDocument, otherKeyPair.getPublic());
        log.info("Verification result with non-matching public key: {}", verified);

        Assertions.assertFalse(verified,
                "Proof must not be verified with a public key that does not belong to the signing key.");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "https://smart.who.int/trust/tng-context/v1-DEV.jsonld",
        "https://smart.who.int/trust/tng-context/v1-UAT.jsonld",
        "https://smart.who.int/trust/tng-context/v1.jsonld"
    })
    void shouldVerifyProofOfDidDocumentUsingTngContext(String tngContext) throws Exception {
        KeyPair keyPair = DidTestHelper.generateEcKeyPair();
        String unsignedDidDocument = DidTestHelper.buildUnsignedDidDocument((ECPublicKey) keyPair.getPublic())
                .replace("\"https://w3id.org/security/suites/jws-2020/v1\"",
                        "\"https://w3id.org/security/suites/jws-2020/v1\", \"" + tngContext + "\"")
                .replace("\"type\": \"JsonWebKey2020\",",
                        "\"type\": \"JsonWebKey2020\", \"domain\": {\"code\": \"#DCC\"},"
                                + " \"participant\": {\"code\": \"#XXU\"}, \"keyusage\": {\"code\": \"#DSC\"},");

        String signedDidDocument = DidTestHelper.signDidDocument(
                (ECPrivateKey) keyPair.getPrivate(), unsignedDidDocument, didContextLoader);

        Assertions.assertTrue(didVerificationService.verify(signedDidDocument, keyPair.getPublic()),
                "Proof of a DID document using the TNG context " + tngContext + " should be verified.");
    }

    private String signDidDocument(KeyPair keyPair) throws Exception {
        return DidTestHelper.signDidDocument((ECPrivateKey) keyPair.getPrivate(),
                (ECPublicKey) keyPair.getPublic(), didContextLoader);
    }
}
