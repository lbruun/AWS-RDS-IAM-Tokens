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

import java.nio.charset.StandardCharsets;

/**
 * Utility for URI encoding.
 * 
 * @author lbruun
 */
public class UriUtils {

    private UriUtils() {
    }

    /**
     * URI encoding (aka percent-encoding) exactly as specified by Amazon.
     * This method is not designed for general URI encoding use, it is
     * specifically for use in <i>AWS Signature V4</i> generation.
     * 
     * @param input the string to encode
     * @param encodeSlash if '/' should be encoded or not
     * @return percent-encoded result
     */
    public static String uriEncode(CharSequence input, boolean encodeSlash) {
        if (input == null) {
            return null;
        }
        if (input.length() == 0) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '~' || ch == '.') {
                result.append(ch);
            } else if (ch == '/') {
                result.append(encodeSlash ? "%2F" : ch);
            } else {
                if (ch < 128) {  // is US_ASCII ?
                    result.append('%');
                    result.append(HexUtils.byteToHex((byte)ch, HexUtils.Case.UPPER));
                } else {
                    byte[] utf8Bytes = (new String(new char[]{ch})).getBytes(StandardCharsets.UTF_8);
                    for(byte b: utf8Bytes) {
                        result.append('%');
                        result.append(HexUtils.byteToHex(b, HexUtils.Case.UPPER));
                    }
                }
            }
        }
        return result.toString();
    }
}
