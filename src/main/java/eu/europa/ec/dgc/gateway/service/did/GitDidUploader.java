/*-
 * ---license-start
 * WHO Digital Documentation Covid Certificate Gateway Service / ddcc-gateway
 * ---
 * Copyright (C) 2022 - 2024 T-Systems International GmbH and all other contributors
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

package eu.europa.ec.dgc.gateway.service.did;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Service;

@ConditionalOnExpression("'${dgc.did.didUploadProvider}'.contains('git')")
@Service
@Slf4j
public class GitDidUploader implements DidUploader {
    
    private final DgcConfigProperties configProperties;    
    
    public GitDidUploader(DgcConfigProperties configProperties) {
        this.configProperties = configProperties;        
    }
    
    
    @Override
    public void uploadDid(byte[] content) {
        Path targetDirectory = Paths.get(configProperties.getDid().getGit().getWorkdir() 
               + File.separator 
               + configProperties.getDid().getGit().getPrefix());
        
        deleteDirectoryAndContents(new File(configProperties.getDid().getGit().getWorkdir()));
        
        try {
            Git.cloneRepository()
            .setURI(configProperties.getDid().getGit().getUrl())
            .setDirectory(new File(configProperties.getDid().getGit().getWorkdir()))
            .setCredentialsProvider(
                new UsernamePasswordCredentialsProvider(
                "anonymous", configProperties.getDid().getGit().getPat()))
                .call();
        } catch (Exception e) {
            log.error("Failed to clone repository {}: {}",
                      configProperties.getDid().getGit().getUrl(), e.getMessage());
        }
        
        try {
            if (!targetDirectory.toFile().exists()) {
                targetDirectory.toFile().mkdir();
            }
            File outputFile = new File(targetDirectory.toString() + File.separator + "did.json");
            try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
                outputStream.write(content);
            } catch (Exception ex) {
                log.error("Error occured while creating file : {}", outputFile.getPath());
            }
            Git git = Git.open(new File(configProperties.getDid().getGit().getWorkdir()));
            git.add().addFilepattern(".").call();
            git.commit().setMessage("Added DID files on " + Instant.now()).call();
            git.push().setCredentialsProvider(new UsernamePasswordCredentialsProvider(
                "anonymous", configProperties.getDid().getGit().getPat())).call();
            git.close();
            log.info("Successfully uploaded DID files to Git repository {}",
                     configProperties.getDid().getGit().getUrl());
        } catch (GitAPIException | IOException e) {
            log.error("Error during Git commit & push: {}",e.getMessage());
        }
        
    }
    
    @Override
    public void uploadDid(String subContainer, byte[] content) {
              
        log.trace("Upload not required");
    }

    private void deleteDirectoryAndContents(File directory) {
        if (directory.isDirectory()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    deleteDirectoryAndContents(file);
                }
            }
        }
        directory.delete();
    }    
    
}
