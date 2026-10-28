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

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.did.DidMethodDriver;
import eu.europa.ec.dgc.did.DidResolver;
import eu.europa.ec.dgc.did.DidWebDriver;
import eu.europa.ec.dgc.did.UniversalDidResolver;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.List;
import javax.net.ssl.SSLContext;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DidResolverConfig {

    /**
     * Creates a {@link DidResolver} bean backed by the {@link UniversalDidResolver}.
     *
     * <p>Uses a dedicated HTTP client for did:web resolution with TLS v1.2 and HTTP/1.1
     * to avoid intermittent TLS handshake failures with raw.githubusercontent.com.
     *
     * @param objectMapper mapper used by the DID web driver to deserialize DID documents
     * @return the DID resolver instance
     */
    @Bean
    public DidResolver didResolver(ObjectMapper objectMapper) {
        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(null, null, null);
        } catch (GeneralSecurityException e) {
            throw new BeanInitializationException("Failed to initialize SSL context for DID resolver.", e);
        }

        HttpClient didHttpClient = HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(30))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .version(HttpClient.Version.HTTP_1_1)
                .build();

        List<DidMethodDriver> drivers = List.of(new DidWebDriver(didHttpClient, objectMapper));
        return new UniversalDidResolver(drivers);
    }
}
