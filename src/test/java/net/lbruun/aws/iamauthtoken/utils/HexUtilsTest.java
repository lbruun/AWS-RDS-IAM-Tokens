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

import net.lbruun.aws.iamauthtoken.utils.HexUtils;
import java.nio.charset.StandardCharsets;
import net.lbruun.aws.iamauthtoken.utils.HexUtils.Case;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author lbruun
 */
public class HexUtilsTest {
    
    @Test
    public void testBytesToHex() {
        String result1 = HexUtils.bytesToHexStr(
                "abc .&/".getBytes(StandardCharsets.US_ASCII), Case.UPPER);
        assertEquals("616263202E262F", result1);
        
        String result2 = HexUtils.bytesToHexStr(
                "Ærø Å".getBytes(StandardCharsets.UTF_8), Case.LOWER);
        assertEquals("c38672c3b820c385", result2);
    }
    
}
