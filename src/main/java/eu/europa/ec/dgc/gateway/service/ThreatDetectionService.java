package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.client.cloudmersive.CloudmersiveClient;
import eu.europa.ec.dgc.gateway.model.CloudmersiveThreatDetectionResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class ThreatDetectionService {

    private final CloudmersiveClient cloudmersiveClient;

    /**
     * Detects threats in a string content using cloudmersive service.
     * @param content string content to be checked
     * @return true if threat is detected, false otherwise
     */
    public boolean containsThreat(String content) {
        log.info("ThreatDetectionService.detectThreatInString: {}", content);

        CloudmersiveThreatDetectionResponse cloudMersiveResponse = cloudmersiveClient.detectThreatInString(content);
        if (cloudMersiveResponse == null) {
            log.error("ThreatDetectionService.detectThreatInString: cloudMersiveResponse is null");
            return false;
        } else {
            log.info("ThreatDetectionService.detectThreatInString: cloudMersiveResponse is not null %s",
                    cloudMersiveResponse.toString());
        }

        return !cloudMersiveResponse.getCleanResult();
    }

}
