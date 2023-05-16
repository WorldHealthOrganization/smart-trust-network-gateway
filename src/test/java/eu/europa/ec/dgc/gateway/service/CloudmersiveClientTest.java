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
        System.out.println(cloudmersiveThreatDetectionResponse.toString());
        Assertions.assertFalse(cloudmersiveThreatDetectionResponse.getCleanResult());
    }

}
