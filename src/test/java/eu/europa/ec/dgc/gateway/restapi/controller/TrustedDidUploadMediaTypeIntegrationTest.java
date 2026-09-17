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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import eu.europa.ec.dgc.did.DidResolver;
import eu.europa.ec.dgc.gateway.testdata.DidTestHelper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class TrustedDidUploadMediaTypeIntegrationTest {

    private static final String DID_DOCUMENT = DidTestHelper.buildUploadDidDocument();

    @MockBean
    DidResolver didResolver;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void testUploadAcceptsDidLdJsonContentType() throws Exception {
        mockResolutionFailure();

        mockMvc.perform(post("/trusted-did")
                .contentType(MediaType.valueOf("application/did+ld+json"))
                .content(DID_DOCUMENT))
            .andExpect(status().isNotFound());
    }

    @Test
    void testUploadAcceptsDidContentType() throws Exception {
        mockResolutionFailure();

        mockMvc.perform(post("/trusted-did")
                .contentType(MediaType.valueOf("application/did"))
                .content(DID_DOCUMENT))
            .andExpect(status().isNotFound());
    }

    private void mockResolutionFailure() {
        when(didResolver.resolve(anyString())).thenReturn(DidTestHelper.notFoundResult());
    }
}
