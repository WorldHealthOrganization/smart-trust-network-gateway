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

package eu.europa.ec.dgc.gateway.client.cloudmersive;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import feign.Client;
import feign.httpclient.ApacheHttpClient;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.SSLContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class CloudmersiveClientConfig {

    private final DgcConfigProperties config;

    /**
     * Configure the client depending on the ssl properties.
     *
     * @return an Apache Http Client with or without SSL features
     */
    @Bean
    public Client cloudmersiveClient() throws NoSuchAlgorithmException {
        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();

        httpClientBuilder.setSSLContext(SSLContext.getDefault());
        httpClientBuilder.setSSLHostnameVerifier(new DefaultHostnameVerifier());

        // Set authentication via API Key
        Header header = new BasicHeader("Apikey", config.getCloudmersive().getApiKey());
        httpClientBuilder.setDefaultHeaders(java.util.Arrays.asList(header));

        if (config.getJrc().getProxy().getHost() != null
            && config.getCloudmersive().getProxy().getPort() != -1
            && !config.getCloudmersive().getProxy().getHost().isEmpty()) {
            log.info("Using Proxy for JRC Connection");
            // Set proxy
            httpClientBuilder.setProxy(new HttpHost(
                config.getCloudmersive().getProxy().getHost(),
                config.getCloudmersive().getProxy().getPort()
            ));

            // Set proxy authentication
            if (config.getCloudmersive().getProxy().getUsername() != null
                && config.getCloudmersive().getProxy().getPassword() != null
                && !config.getCloudmersive().getProxy().getUsername().isEmpty()
                && !config.getCloudmersive().getProxy().getPassword().isEmpty()) {

                log.info("Using Proxy with Authentication for JRC Connection");

                CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
                credentialsProvider.setCredentials(
                    new AuthScope(
                        config.getCloudmersive().getProxy().getHost(),
                        config.getCloudmersive().getProxy().getPort()),
                    new UsernamePasswordCredentials(
                        config.getCloudmersive().getProxy().getUsername(),
                        config.getCloudmersive().getProxy().getPassword()));

                httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
            }


        } else {
            log.info("Using no proxy for Cloudmersive Connection");
        }



        return new ApacheHttpClient(httpClientBuilder.build());
    }
}
