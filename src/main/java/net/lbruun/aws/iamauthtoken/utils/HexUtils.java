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

/**
 * Utilities for converting byte(s) into hexadecimal representation.
 * @author lbruun
 */
public class HexUtils {

    private static final char[] HEX_CHARS_LOWER = 
            new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    private static final char[] HEX_CHARS_UPPER = 
            new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    
    public enum Case {
        LOWER,
        UPPER
    }

    private HexUtils() {
    }
    
    /**
     * Converts a byte into hexadecimal representation and 
     * put the result into a target array at a specified location.
     * @param b input to convert to hex
     * @param target the char array where the result will be put
     * @param targetStartPos where to put the hex chars in {@code target}. 
     * @param caseType if the hexadecimal representation should be in upper or lower case
     */
    private static void putHexIntoCharArray(byte b, char[] target, int targetStartPos, Case caseType) {
        int octet = b & 0xFF;
        char[] hexArray = (caseType == Case.UPPER) ? HEX_CHARS_UPPER : HEX_CHARS_LOWER;
        target[targetStartPos] = hexArray[octet >>> 4];
        target[targetStartPos+1] = hexArray[octet & 0x0F];
    }

    /**
     * Converts a single byte to its hexadecimal representation.
     * @param b input
     * @param caseType if the hexadecimal representation should be in upper or lower case
     * @return char array of length 2
     */
    public static char[] byteToHex(byte b, Case caseType) {
        char[] hexChars = new char[2];
        putHexIntoCharArray(b, hexChars, 0, caseType);
        return hexChars;
    }

    /**
     * Converts a byte array to its hexadecimal representation.
     * 
     * <p>
     * This method is slightly faster than 
     * {@link #bytesToHexStr(byte[], net.lbruun.aws.iamauthtoken.HexUtils.Case) bytesToHexStr}.
     * @param bytes input
     * @param caseType if the hexadecimal representation should be in upper or lower case
     * @return hexadecimal representation
     */
    public static char[] bytesToHex(byte[] bytes, Case caseType) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            putHexIntoCharArray(bytes[i], hexChars, i * 2, caseType);
        }
        return hexChars;
    }
    
    /**
     * Converts a byte array to its hexadecimal representation.
     * @param bytes input
     * @param caseType if the hexadecimal representation should be in upper or lower case
     * @return hexadecimal representation
     */
    public static String bytesToHexStr(byte[] bytes, Case caseType) {
        return new String(bytesToHex(bytes, caseType));
    }
}
