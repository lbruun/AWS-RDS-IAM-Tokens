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
package net.lbruun.aws.iamauthtoken.utils;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Utilities for working with AWS Region identifiers.
 * @author lbruun
 */
public class RegionUtils {

    /**
     * List of known AWS Region identifiers.
     */
    public static final List<String> KNOWN_REGION_IDS_LIST = Arrays.asList(new String[]{
        "ap-south-1",
         "eu-south-1",
         "us-gov-east-1",
         "ca-central-1",
         "eu-central-1",
         "us-west-1",
         "us-west-2",
         "af-south-1",
         "eu-north-1",
         "eu-west-3",
         "eu-west-2",
         "eu-west-1",
         "ap-northeast-2",
         "ap-northeast-1",
         "me-south-1",
         "sa-east-1",
         "ap-east-1",
         "cn-north-1",
         "us-gov-west-1",
         "ap-southeast-1",
         "ap-southeast-2",
         "us-iso-east-1",
         "us-east-1",
         "us-east-2",
         "cn-northwest-1",
         "us-isob-east-1",
         "aws-global",
         "aws-cn-global",
         "aws-us-gov-global",
         "aws-iso-global",
         "aws-iso-b-global"
    });
    
    
    private RegionUtils() {
    }
    
    
    /**
     * Derives an AWS Region Id from a hostname.
     * Often it is possible to determine the AWS Region from a RDS hostname. 
     * 
     * <p>
     * Examples of RDS hostnames:
     * <ul>
     *    <li>{@code mydbcluster.cluster-123456789012.us-east-1.rds.amazonaws.com} 
     *        (Aurora cluster)</li>
     *    <li>{@code myinstance.123456789012.us-east-1.rds.amazonaws.com} 
     *        (standard instance)</li>
     * </ul>
     * <p>
     * For such values the region can safely be derived as {@code us-east-1}.
     * 
     * <p>
     * The method errs on the side of caution. This means that the region string
     * found within the hostname string <i>must</i> match a {@link #KNOWN_REGION_IDS_LIST known region identifier}.
     * For example, for input {@code myinstance.123456789012.atlanta.rds.amazonaws.com}
     * the resulting region id is not "atlanta", because "atlanta" is not a known
     * region identifier. In such case an empty Optional will be returned.
     * 
     * @param hostname hostname, not IP address, case is irrelevant
     * @return Optional containing regionId, it will be empty if the region
     *    cannot be safely determined.
     */
    public static Optional<String> getRegionIdFromHostname(String hostname) {
        if (hostname == null || hostname.length() <= 3) {
            return Optional.empty();
        }
        String hostnameLower = hostname.toLowerCase(Locale.US);
        
        String suffix = ".rds.amazonaws.com";
        if (hostnameLower.endsWith(suffix)) {
            
            // Example fragment: mydb.eb6biuyqt2qc.eu-central-1.rds.amazonaws.com
            String fragment = hostnameLower.substring(0, hostnameLower.length() - suffix.length());
            
            int lastDot = fragment.lastIndexOf('.');
            if (lastDot > 0 && (lastDot < fragment.length()-1)) {
                String regionStr = fragment.substring(lastDot + 1);                
                for(String knownRegionId : KNOWN_REGION_IDS_LIST) {
                    if (regionStr.equals(knownRegionId)) {
                        return Optional.of(regionStr);
                    }
                }
            }
        }
        return Optional.empty();
    }
    
}
