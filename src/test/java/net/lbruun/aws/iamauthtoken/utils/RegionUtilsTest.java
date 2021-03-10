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

import net.lbruun.aws.iamauthtoken.utils.RegionUtils;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import software.amazon.awssdk.regions.Region;

public class RegionUtilsTest {

    @Test
    public void testDeriveRegionFromHostname() {
        Optional<String> region1 = RegionUtils.getRegionIdFromHostname("mydbcluster.cluster-123456789012.us-east-1.rds.amazonaws.com");
        assertEquals(Region.US_EAST_1.id(), region1.get());

        Optional<String> region2 = RegionUtils.getRegionIdFromHostname("mydbcluster.cluster-123456789012.us-east-1..rds.amazonaws.com");
        assertEquals(Optional.empty(), region2);

        Optional<String> region3 = RegionUtils.getRegionIdFromHostname("mydbcluster.cluster-123456789012.foobar.rds.amazonaws.com");
        assertEquals(Optional.empty(), region3);

        Optional<String> region4 = RegionUtils.getRegionIdFromHostname("mydbcluster.cluster-123456789012...us-east-1.rds.amazonaws.com");
        assertEquals(Optional.empty(), region3);
    }
}
