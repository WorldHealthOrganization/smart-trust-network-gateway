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

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class DidUploadInvoker {
    
    @Autowired
    List<DidUploader> didUploaders;
    
    /**
     * Method invokes the DID document upload of all the DidUploader implementations. 
     * @param content DID document in byte array form
     */
    public void uploadDid(byte[] content) {
        for (DidUploader didUploader : didUploaders) {
            didUploader.uploadDid(content);
        }
    }
    
    /**
     * Method invokes the DID document upload of all the DidUploader implementations.
     * @param subDirectory is a sub folder
     * @param content DID document in byte array form
     */
    public void uploadDid(String subDirectory, byte[] content) {
        for (DidUploader didUploader : didUploaders) {
            didUploader.uploadDid(subDirectory, content);
        }
    }

}
