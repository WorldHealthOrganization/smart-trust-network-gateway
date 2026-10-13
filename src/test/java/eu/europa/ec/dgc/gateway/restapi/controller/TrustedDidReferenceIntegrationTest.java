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

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import eu.europa.ec.dgc.did.DidResolver;
import eu.europa.ec.dgc.did.model.DidDocument;
import eu.europa.ec.dgc.did.model.DidResolutionResult;
import eu.europa.ec.dgc.gateway.testdata.DidTestHelper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class TrustedDidReferenceIntegrationTest {

    private static final String DID = DidTestHelper.DID;

    @MockBean
    DidResolver didResolver;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void testGetDidDocumentByDid() throws Exception {
        DidDocument didDocument = new DidDocument();
        didDocument.setId(DID);

        when(didResolver.resolve(DID)).thenReturn(DidResolutionResult.success(didDocument));

        mockMvc.perform(get("/trusted-did-reference").param("did", DID))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(DID));
    }

    @Test
    void testGetDidDocumentReturnsNotFoundForUnresolvableDid() throws Exception {
        when(didResolver.resolve(anyString())).thenReturn(DidTestHelper.notFoundResult());

        mockMvc.perform(get("/trusted-did-reference").param("did", DID))
            .andExpect(status().isNotFound());
    }

    @Test
    void testGetDidDocumentReturnsBadRequestForInvalidDid() throws Exception {
        when(didResolver.resolve(anyString())).thenReturn(DidTestHelper.invalidDidResult());

        mockMvc.perform(get("/trusted-did-reference").param("did", "not-a-did"))
            .andExpect(status().isBadRequest());
    }
}
