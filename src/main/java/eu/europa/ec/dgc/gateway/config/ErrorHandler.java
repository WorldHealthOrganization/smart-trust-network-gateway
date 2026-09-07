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

import eu.europa.ec.dgc.gateway.exception.DgcgResponseException;
import eu.europa.ec.dgc.gateway.restapi.dto.ProblemReportDto;
import jakarta.validation.ConstraintViolationException;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
@Configuration
@RequiredArgsConstructor
@Slf4j
public class ErrorHandler extends ResponseEntityExceptionHandler {

    /**
     * Handles {@link ConstraintViolationException} when a validation failed.
     *
     * @param e the thrown {@link ConstraintViolationException}
     * @return A ResponseEntity with a ErrorMessage inside.
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ProblemReportDto> handleException(ConstraintViolationException e) {
        return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .contentType(MediaType.APPLICATION_JSON)
            .body(new ProblemReportDto("0x001", "Validation Error", "", e.getMessage()));
    }

    /**
     * Global Exception Handler to wrap exceptions into a readable JSON Object.
     *
     * @param e the thrown exception
     * @return ResponseEntity with readable data.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemReportDto> handleException(Exception e) {

        if (e instanceof DgcgResponseException de) {
            return ResponseEntity
                .status(de.getStatus())
                .contentType(MediaType.APPLICATION_JSON)
                .body(new ProblemReportDto(de.getCode(), de.getProblem(), de.getSentValues(), de.getDetails()));
        } else {
            log.error("Uncaught exception", e);
            return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON)
                .body(new ProblemReportDto("0x008", "Internal Server Error", "", e.getMessage()));
        }
    }

    /**
     * Handles {@link MethodArgumentNotValidException} thrown when a {@code @Valid} request body fails validation.
     *
     * @param e       the thrown {@link MethodArgumentNotValidException}
     * @param headers the headers of the request
     * @param status  the status of the response
     * @param request the current request
     * @return A ResponseEntity with a ProblemReportDto describing the field errors.
     */
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
        MethodArgumentNotValidException e, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        String details = e.getBindingResult().getFieldErrors().stream()
            .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
            .collect(Collectors.joining("; "));

        return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .contentType(MediaType.APPLICATION_JSON)
            .body(new ProblemReportDto("0x001", "Validation Error", "", details));
    }

    /**
     * Handles {@link HttpMessageNotReadableException} thrown when the request body cannot be parsed.
     *
     * @param e       the thrown {@link HttpMessageNotReadableException}
     * @param headers the headers of the request
     * @param status  the status of the response
     * @param request the current request
     * @return A ResponseEntity with a ProblemReportDto describing the parse error.
     */
    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(
        HttpMessageNotReadableException e, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .contentType(MediaType.APPLICATION_JSON)
            .body(new ProblemReportDto(
                "0x002", "Malformed Request Body", "", e.getMostSpecificCause().getMessage()));
    }
}
