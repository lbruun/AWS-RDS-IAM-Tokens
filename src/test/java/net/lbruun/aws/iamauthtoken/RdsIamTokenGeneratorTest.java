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
package net.lbruun.aws.iamauthtoken;

import net.lbruun.aws.iamauthtoken.comparison.SDKv2RdsIamTokenGenerator;
import net.lbruun.aws.iamauthtoken.comparison.SDKv1RdsIamTokenGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

public class RdsIamTokenGeneratorTest {

    @Test
    public void testGenerateToken() {
        // Input data
        String awsAccessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        String regionId = "eu-central-1";
        String hostname = "mypsql.ca8biuyqt0qc.eu-central-1.rds.amazonaws.com";
        String dbUsername = "db_userx_æøå";
        int portNo = 5432;

        // Use a fixed clock 
        
        long fixedDateMillis = 1577836800000L;   // 2020-01-01 00:00:00 Z
        Clock clock = Clock.fixed(Instant.ofEpochMilli(fixedDateMillis), ZoneOffset.UTC);
        
        RdsIamToken token = RdsIamTokenGenerator.getRdsIamToken(
                RdsIamTokenGenerator.Parameters.builder()
                        .awsAccessKeyId(awsAccessKeyId)
                        .awsSecretKey(awsSecretKey)
                        .regionId(regionId)
                        .hostname(hostname)
                        .portNo(portNo)
                        .dbUsername(dbUsername)
                        .clock(clock)
                        .build());
        
        String sdkV1Token
                = SDKv1RdsIamTokenGenerator.generateAuthToken(
                        awsAccessKeyId,
                        awsSecretKey,
                        regionId,
                        hostname,
                        portNo,
                        dbUsername,
                        clock);
        
        String sdkV2Token
                = SDKv2RdsIamTokenGenerator.generateAuthToken(
                        awsAccessKeyId,
                        awsSecretKey,
                        regionId,
                        hostname,
                        portNo,
                        dbUsername,
                        clock);
        
        // Compare
        assertEquals(sdkV1Token, token.getToken());  // compare against SDK v1
        assertEquals(sdkV2Token, token.getToken());  // compare against SDK v2
    }


    @Test
    public void testGenerateAuthenticationTokenParamBuilder() {
        
        // Test what will happen if the 'regionId' is not explicitly
        // specified.
        String awsAccessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        String hostname = "mypsql.ca8biuyqt0qc.eu-central-1.rds.amazonaws.com";
        String dbUsername = "db_userx_æøå";
        int portNo = 5432;

        
        RdsIamTokenGenerator.Parameters params = RdsIamTokenGenerator.Parameters.builder()
                .awsAccessKeyId(awsAccessKeyId)
                .awsSecretKey(awsSecretKey)
                .hostname(hostname)
                .portNo(portNo)
                .dbUsername(dbUsername)
                .build();
        
        assertEquals("eu-central-1", params.getRegionId());
    }

}
