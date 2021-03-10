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

import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.SdkClock;
import com.amazonaws.auth.StaticSignerProvider;
import com.amazonaws.auth.presign.PresignerParams;
import com.amazonaws.internal.auth.SignerProvider;
import com.amazonaws.services.rds.auth.GetIamAuthTokenRequest;
import com.amazonaws.services.rds.auth.RdsIamAuthTokenGenerator;
import com.amazonaws.services.rds.auth.SDKv1Bridge;
import java.time.Clock;
import java.util.Date;

/**
 * Generates RDS IAM Tokens based on AWS SDK v1. 
 * 
 * Allows for a fixed clock for testing purpose.
 * 
 * @author lbruun
 */
public class SDKv1RdsIamTokenGenerator {

    public static String generateAuthToken(
            String awsAccessKeyId, 
            String awsSecretKey, 
            String regionId, 
            String hostname, 
            int portNo, 
            String dbUsername,
            Clock clock) {

        SdkClock sdkClock = getSdkClock(clock);
        PresignerParams presignerParams = PresignerParams.builder()
                .credentialsProvider(getCredentialsProvider(awsAccessKeyId, awsSecretKey))
                .signerProvider(createSignerProvider(regionId, sdkClock))
                .clock(sdkClock)
                .build();

        RdsIamAuthTokenGenerator generator = SDKv1Bridge.getGenerator(presignerParams);

        String authToken = generator.getAuthToken(GetIamAuthTokenRequest.builder()
                        .hostname(hostname)
                        .port(portNo)
                        .userName(dbUsername)
                        .build());

        return authToken;
    }

    private static SignerProvider createSignerProvider(String region, SdkClock sdkClock) {
        AWS4Signer signer = new AWS4Signer(sdkClock);
        signer.setOverrideDate(new Date(sdkClock.currentTimeMillis()));
        signer.setRegionName(region);
        signer.setServiceName("rds-db");
        return new StaticSignerProvider(signer);
    }
    
    
    private static AWSStaticCredentialsProvider getCredentialsProvider(String accessKey, String secretKey) {
       return new AWSStaticCredentialsProvider( new BasicAWSCredentials(accessKey, secretKey));
    }

    private static SdkClock getSdkClock(Clock clock) {
        return clock::millis;
    }
}
