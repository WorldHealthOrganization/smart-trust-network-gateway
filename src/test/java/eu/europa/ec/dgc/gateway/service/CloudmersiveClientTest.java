/*-
 * ---license-start
 * WHO Digital Documentation Covid Certificate Gateway Service / ddcc-gateway
 * ---
 * Copyright (C) 2022 - 2023 T-Systems International GmbH and all other contributors
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
import eu.europa.ec.dgc.gateway.model.CloudmersiveThreatDetectionResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class CloudmersiveClientTest {

    @Autowired
    private CloudmersiveClient cloudmersiveClient;

    @Disabled //uses real client and cloudmersive api key (to be adapted for local testing)
    @Test
    public void test_cloudmersive_client() {
        String threatContent = "';alert(String.fromCharCode(88,83,83))\nalert(String.fromCharCode(88,83,83))\n></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT> ";


        CloudmersiveThreatDetectionResponse cloudmersiveThreatDetectionResponse = cloudmersiveClient.detectThreatInString(threatContent);
        Assertions.assertFalse(cloudmersiveThreatDetectionResponse.getCleanResult());
    }

}
