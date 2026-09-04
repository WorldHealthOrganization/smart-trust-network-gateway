package eu.europa.ec.dgc.gateway.restapi.dto.did;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class TrustedDidPublicKeyDto {

    private String publicKey;

    private boolean verified;

    private String message;
}
