/*
 * Copyright 2021 lbruun.net.
 *
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
 */
package net.lbruun.aws.iamauthtoken.comparison;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.signer.Aws4Signer;
import software.amazon.awssdk.auth.signer.params.Aws4PresignerParams;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.utils.StringUtils;

/**
 * Generates RDS IAM Tokens based on AWS SDK v2.
 * 
 * Allows for a fixed clock for testing purpose.
 * 
 * @author lbruun
 */
public class SDKv2RdsIamTokenGenerator {

    // The time the IAM token is good for. 
    // https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html
    private static final Duration TOKEN_TTL = Duration.ofMinutes(15);


    /**
     * Single constructor. Typically there is only a single instance of 
     * {@code RdsIamTokenGenerator} in an application.
     */
    private SDKv2RdsIamTokenGenerator() {
    }
    


    public static  String generateAuthToken(
            String awsAccessKeyId, 
            String awsSecretKey, 
            String regionId, 
            String hostname, 
            int portNo, 
            String dbUsername,
            Clock clock) {
        SDKv2RdsIamTokenGenerator generator = new SDKv2RdsIamTokenGenerator();
        
        // The following is from 
        // https://github.com/aws/aws-sdk-java-v2/pull/2057
        // (at the time of writing this code this PR was not merged)
    
        
        SdkHttpFullRequest httpRequest = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.GET)
                .protocol("https")
                .host(hostname)
                .port(portNo)
                .encodedPath("/")
                .putRawQueryParameter("Action", "connect")
                .putRawQueryParameter("DBUser", dbUsername)
                .build();

        Aws4Signer signer = Aws4Signer.create();

        Instant expirationTime = Instant.now(clock).plus(TOKEN_TTL);
        Aws4PresignerParams presignRequest = Aws4PresignerParams.builder()
                .signingClockOverride(clock)
                .expirationTime(expirationTime)
                .awsCredentials(AwsBasicCredentials.create(awsAccessKeyId, awsSecretKey))
                .signingName("rds-db")
                .signingRegion(Region.of(regionId))
                .build();

        SdkHttpFullRequest fullRequest = signer.presign(httpRequest, presignRequest);
        String signedUrl = fullRequest.getUri().toString();

        // Format should be: <hostname>>:<port>>/?Action=connect&DBUser=<username>>&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expi...
        return  StringUtils.replacePrefixIgnoreCase(signedUrl, "https://", "");
    }
}
