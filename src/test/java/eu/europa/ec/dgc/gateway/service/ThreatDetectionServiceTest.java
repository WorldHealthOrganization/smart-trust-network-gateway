package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.client.cloudmersive.CloudmersiveClient;
import eu.europa.ec.dgc.gateway.model.CloudmersiveThreatDetectionResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import static org.mockito.Mockito.when;

@SpringBootTest
public class ThreatDetectionServiceTest {

    @MockBean
    private CloudmersiveClient cloudmersiveClient;

    @Autowired
    private ThreatDetectionService threatDetectionService;

    @Test
    public void test_threat_detected() {
        String threatContent = "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";\n" +
                "alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--\n" +
                "></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>";

        CloudmersiveThreatDetectionResponse cloudmersiveThreatDetectionResponse = new CloudmersiveThreatDetectionResponse();
        cloudmersiveThreatDetectionResponse.setCleanResult(false);

        when(cloudmersiveClient.detectThreatInString(threatContent)).thenReturn(cloudmersiveThreatDetectionResponse);

        boolean isThreatContent = threatDetectionService.containsThreat(threatContent);

        Assertions.assertTrue(isThreatContent);
    }


    @Test
    public void test_no_threat_detected() {
        String threatContent = "no threat contained in content";

        CloudmersiveThreatDetectionResponse cloudmersiveThreatDetectionResponse = new CloudmersiveThreatDetectionResponse();
        cloudmersiveThreatDetectionResponse.setCleanResult(true);

        when(cloudmersiveClient.detectThreatInString(threatContent)).thenReturn(cloudmersiveThreatDetectionResponse);

        boolean isThreatContent = threatDetectionService.containsThreat(threatContent);

        Assertions.assertFalse(isThreatContent);
    }

}
