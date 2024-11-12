package eu.europa.ec.dgc.gateway.service.did;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@ConditionalOnProperty(name = "dgc.did.didUploadProvider", havingValue = "dummy")
@Service
@Slf4j
public class DummyGitDidUploader implements DidUploader {

    @Override
    public void uploadDid(byte[] content) {
        log.info("Uploaded {} bytes in git", content.length);
    }

    @Override
    public void uploadDid(String subContainer, byte[] content) {
        log.info("Uploaded {} bytes in git to subContainer {}", content.length, subContainer);
    }

}
