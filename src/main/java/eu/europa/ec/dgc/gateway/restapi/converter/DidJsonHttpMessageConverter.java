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

package eu.europa.ec.dgc.gateway.restapi.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;

/**
 * Read-only JSON converter for the {@code application/did} media type.
 *
 * <p>DID documents may be submitted as {@code application/did}, which - unlike
 * {@code application/did+ld+json} - is not covered by the {@code application/*+json} wildcard
 * supported by the default Jackson converter. This converter is scoped to that single media type
 * and refuses to write, so response content negotiation of existing endpoints stays untouched.
 */
public class DidJsonHttpMessageConverter extends MappingJackson2HttpMessageConverter {

    public static final MediaType CONTENT_TYPE_DID = new MediaType("application", "did");
    public static final String CONTENT_TYPE_DID_VALUE = "application/did";

    public DidJsonHttpMessageConverter(ObjectMapper objectMapper) {
        super(objectMapper);
        setSupportedMediaTypes(List.of(CONTENT_TYPE_DID));
    }

    @Override
    public boolean canWrite(Class<?> clazz, MediaType mediaType) {
        return false;
    }
}
