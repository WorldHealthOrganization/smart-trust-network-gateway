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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties("dgc")
public class DgcConfigProperties {

    private final CertAuth certAuth = new CertAuth();
    private final KeyStoreWithAlias trustAnchor = new KeyStoreWithAlias();

    private String validationRuleSchema;

    private JrcConfig jrc = new JrcConfig();

    private Revocation revocation = new Revocation();

    private SignerInformation signerInformation = new SignerInformation();

    private Federation federation = new Federation();

    private TrustedCertificates trustedCertificates = new TrustedCertificates();

    private DidConfig did = new DidConfig();

    private CloudmersiveConfig cloudmersive = new CloudmersiveConfig();

    private CountryCodeMap countryCodeMap = new CountryCodeMap();

    @Getter
    @Setter
    public static class DidConfig {

        private String didId;
        private String didController;
        private String trustListIdPrefix;
        private String trustListControllerPrefix;
        private String ldProofVerificationMethod;
        private String ldProofDomain;
        private String ldProofNonce;
        private String didSigningProvider;
        private Boolean includeFederated = false;

        private AzureConfig azure;
        private GitConfig git = new GitConfig();

        private Map<String, String> contextMapping = new HashMap<>();

        @Getter
        @Setter
        public static class AzureConfig {
            private String spId;
            private String spSecret;
            private String spTenant;
            private String secretUrl;
            private String blobEndpoint;
            private String blobContainer;
            private String blobName;
            private ProxyConfig proxy = new ProxyConfig();

        }
    }

    @Getter
    @Setter
    public static class TrustedCertificates {
        private List<String> allowedProperties = new ArrayList<>();
        private List<String> allowedDomains = new ArrayList<>();
    }

    @Getter
    @Setter
    public static class JrcConfig {
        private String url;
        private Integer interval = 21_600_000;
        private ProxyConfig proxy = new ProxyConfig();
    }

    @Getter
    @Setter
    public static class CloudmersiveConfig {

        private String url;
        private String apiKey;
        private Boolean enabled;
        private Integer maxRetries = 3;
        private ProxyConfig proxy = new ProxyConfig();
    }

    @Getter
    @Setter
    public static class ProxyConfig {

        private String host;
        private int port = -1;
        private String username;
        private String password;
    }

    @Getter
    @Setter
    public static class KeyStoreWithAlias {
        private String keyStorePath;
        private String keyStorePass;
        private String certificateAlias;
    }

    @Getter
    @Setter
    public static class CertAuth {

        private final HeaderFields headerFields = new HeaderFields();
        private List<String> certWhitelist;

        @Getter
        @Setter
        public static class HeaderFields {
            private String thumbprint;
            private String distinguishedName;
            private String pem;
        }
    }

    @Getter
    @Setter
    public static class Revocation {
        private int deleteThreshold = 14;
        private Boolean enabled;
    }

    @Getter
    @Setter
    public static class Federation {
        private String gatewayId;
        private String version;
        private String contact;
        private String owner;
        private String signature;

        private String keystorePath;
        private String keystorePassword;
        private String keystoreKeyPassword;
    }

    @Getter
    @Setter
    public static class SignerInformation {
        private int deleteThreshold = 14;
    }

    @Getter
    @Setter
    public static class CountryCodeMap {
        private Map<String, String> virtualCountries = new HashMap<>();
    }

    @Getter
    @Setter
    public static class GitConfig {
        private String prefix;
        private String workdir;
        private String pat;
        private String url;
        private String owner;
        private String branch;
    }
}
