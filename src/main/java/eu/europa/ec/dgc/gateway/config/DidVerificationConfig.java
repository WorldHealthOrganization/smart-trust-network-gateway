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

package eu.europa.ec.dgc.gateway.config;

import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import eu.europa.ec.dgc.did.DidVerificationService;
import foundation.identity.jsonld.ConfigurableDocumentLoader;
import java.io.InputStream;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class DidVerificationConfig {

    private static final String DID_CONTEXT_PATH = "did_contexts/";

    private final DgcConfigProperties configProperties;

    /**
     * Builds the JSON-LD document loader that resolves DID contexts from local resources.
     *
     * @return the configured {@link DocumentLoader}
     */
    @Bean
    public DocumentLoader didContextLoader() {
        Map<URI, JsonDocument> contextMap = new HashMap<>();
        Map<String, String> contextMapping = configProperties.getDid().getContextMapping();

        for (Map.Entry<String, String> entry : contextMapping.entrySet()) {
            String contextFile = entry.getValue();
            try (InputStream inputStream =
                         getClass().getClassLoader().getResourceAsStream(DID_CONTEXT_PATH + contextFile)) {
                if (inputStream == null) {
                    throw new BeanInitializationException("Failed to load DID-Context Document for "
                            + entry.getKey() + ": Resource " + DID_CONTEXT_PATH + contextFile + " not found.");
                }
                contextMap.put(URI.create(entry.getKey()), JsonDocument.of(inputStream));
            } catch (Exception e) {
                throw new BeanInitializationException(
                        "Failed to load DID-Context Document for " + entry.getKey(), e);
            }
        }

        return new ConfigurableDocumentLoader(contextMap);
    }

    /**
     * Creates the DID proof verification service from {@code ddcc-gateway-lib}.
     *
     * @param didContextLoader the JSON-LD document loader for DID contexts
     * @return the DID verification service
     */
    @Bean
    public DidVerificationService didVerificationService(DocumentLoader didContextLoader) {
        return new DidVerificationService(didContextLoader);
    }
}
