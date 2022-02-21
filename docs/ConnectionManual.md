# Onboarding Checklist

## Common Hints

It is highly recommended:
- **to use certificates issued from a public CA which follows the CAB Forum Rules**
- **not to reuse any certificates across the different staging environments**

## Test Environment

For a successfull connection to the gateway there are several steps to prepare: 

 1) Certificates must be prepared for Test Environment (self signed allowed)
    - Authentication: NB<sub>TLS</sub>
    - Upload:   NB<sub>UP</sub>
    - CSCA(s):  NB<sub>CSCA</sub>
 2) Send the Public Keys in PEM Format to the contact of the Test Operator (functional mailbox)
 3) After Onboarding in the Test Environment, check the connectivity with the following command:<br>
  ```curl -vvv -H "Accept: */*" --resolve ****.com:443 --cert "auth_de.pem" --key "key.pem" https://****.com/trustList``` <br>
    You should see a output like: <br>
    ![TrustListOutput](./../images/TrustListResult.PNG)
 4) Test the other Truslist Routes in the same style (e.g. with DSC/CSCA/Upload/Authentication...)
 5) Create an Document Signer Certificate  and sign it by the CSCA
 6) Create an CMS Package with the following Command: 
  ``` 
      openssl x509 -outform der -in cert.pem -out cert.der
      openssl cms -sign -nodetach -in cert.der -signer signing.crt -inkey signing.key -out signed.der -outform DER -binary
      openssl base64 -in signed.der -out cms.b64 -e -A 
  ``` 
   Note: cert.der is your DSC, signing.crt ist the Uploader Certificate. Other content can be took as JSON e.g. Trusted References)
  
 7) Upload the CMS Package to the Gateway<br>
    ```curl -v -X POST -H "Content-Type: application/cms" --cert auth_de.pem --key key.pem --data @cms.b64 https://****.ec.europa.eu/signerCertificate``` <br>
 8) Download the Trustlist again, and check if your DSC is available.
 
 
**Note**: Some versions of curl don't attach the client certificates automatically. This can be checked via
``` curl --version ```
Ensure that the used version is linked to OpenSSL. Especially under Windows (https://curl.se/windows/): 
<br><br>
OpenSSL Test Example (working)<br>
<br>
![Working Setup](./images/OpenSSL.PNG)
<br><br>
WinSSL Test Example (Not working)
<br><br>
![Non Working Setup](./images/WinSSL.PNG)

Note: It may be required that openssl must be compiled on mac os to enable the CMS feature.



    
