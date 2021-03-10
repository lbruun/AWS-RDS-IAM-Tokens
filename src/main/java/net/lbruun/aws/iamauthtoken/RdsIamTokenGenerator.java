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


import net.lbruun.aws.iamauthtoken.utils.Validation;
import net.lbruun.aws.iamauthtoken.utils.UriUtils;
import net.lbruun.aws.iamauthtoken.utils.RegionUtils;
import net.lbruun.aws.iamauthtoken.utils.HexUtils;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import net.lbruun.aws.iamauthtoken.utils.HexUtils.Case;

/**
 * Generates RDS IAM Authentication Tokens.
 * 
 * @author lbruun
 */
public class RdsIamTokenGenerator {
    /**
     * SHA-256 hash of the empty string, converted to hex representation in lower case.
     * This is the 'payload' hashed in the AWS v4 Signature signing process.
     */
    private static final String HEX_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";


    private static final String AWS4_SIGNING_ALGORITHM = "AWS4-HMAC-SHA256";
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final String AWS4_TERMINATOR = "aws4_request";
    private static final String LINE_SEPARATOR = "\n";
    private static final String X_AMZ_ALGORITHM = "X-Amz-Algorithm";
    private static final String X_AMZ_CREDENTIAL = "X-Amz-Credential";
    private static final String X_AMZ_DATE = "X-Amz-Date";
    private static final String X_AMZ_EXPIRES = "X-Amz-Expires";
    private static final String X_AMZ_SIGNATURE = "X-Amz-Signature";
    private static final String X_AMZ_SIGNED_HEADER = "X-Amz-SignedHeaders";
    private static final String SERVICE_NAME = "rds-db";
    private static final String SIGNED_HEADER = "host";
    private static final String HTTP_METHOD = "GET";
    private static final String ACTION = "connect";
    private static final String CANONICAL_URI_RESOURCE = "/";
    
    private static final DateTimeFormatter DT_FORMAT = 
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneId.from(ZoneOffset.UTC));
    private static final DateTimeFormatter D_FORMAT = 
            DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneId.from(ZoneOffset.UTC));

    /**
     * Generates a token which can be used as password when connecting to the
     * RDS instance.
     *
     * <p>
     * Generating a token requires the following input:
     * <ul>
     *    <li>AWS Credentials in the form of a <i>AWS Access Key Id</i> as well as
     *        an <i>AWS Secret Key</i>.</li>
     *    <li>Information about the target RDS instance:
     *        <ul>
     *           <li>Hostname and port of the RDS instance.</li>
     *           <li>Region where the RDS instance is located.</li>
     *           <li>DB username: the database user to authenticate as.</li>
     *        </ul></li>
     * </ul>
     * 
     * <p>
     * No checks are performed on the validity of the input parameters when the token
     * is generated. For example it is perfectly possible to generate
     * a token for an RDS instance which doesn't exist or a DB user which doesn't
     * exist in the target RDS database instance. When the generated token
     * is used to connect to the database -  and if incorrect parameters have been
     * used when the token was generated - it will result in a simple authentication
     * error from the database server without further explanation. It is therefore
     * important to be meticulous with the input parameters.
     * 
     * <p>
     * Generating a token does not involve any form of network traffic. It does,
     * however, involve some lightweight cryptographic calculations. On most
     * servers generating a token will take less than 1 ms (depending on
     * hardware specs).
     *
     * @param parameters
     * @return
     */
    public static RdsIamToken getRdsIamToken(Parameters parameters) {
        try {
            String regionId = parameters.getRegionId();
            String hostname = parameters.getHostname();
            int portNo = parameters.getPortNo();
            String dbUsername = parameters.getDbUsername();
            String awsAccessKeyId = parameters.getAwsAccessKeyId();
            String awsSecretKey = parameters.getAwsSecretKey();
            int expirySeconds = parameters.getExpirySeconds();
            Clock clock = parameters.getClock();
            
            Instant now = Instant.now(clock);
            Instant expirationTime = now.plus(Duration.of(expirySeconds, ChronoUnit.SECONDS));
            
            String dateTimeStr = DT_FORMAT.format(now);
            String dateStr = D_FORMAT.format(now);

            List<QueryParameter> queryParameters = getQueryParameters(dbUsername, awsAccessKeyId, dateStr, dateTimeStr, regionId, expirySeconds);
            String canonicalQueryString = getCanonicalQueryString(queryParameters);
            String queryString = getQueryString(queryParameters);
            String canonicalString = getCanonicalString(canonicalQueryString, hostname, portNo);
            String stringToSign = getStringToSign(dateTimeStr, canonicalString, dateStr, regionId);
            String signature = HexUtils.bytesToHexStr(calculateSignature(stringToSign, awsSecretKey, dateStr, regionId), Case.LOWER);
            
            String token = getFinalToken0(hostname, portNo, queryString, signature);
            
            return RdsIamToken.builder()
                    .awsAccessKeyId(awsAccessKeyId)
                    .expirationTime(expirationTime)
                    .hostname(hostname)
                    .portNo(portNo)
                    .regionId(regionId)
                    .dbUsername(dbUsername)
                    .token(token)
                    .build();
        } catch (GeneralSecurityException ex) {
            // If any method throws this it is really unexpected. It would mean
            // that the JDK dosn't provide the algorithms we expect it should.
            throw new RuntimeException("Unexpected error while generating RDS IAM Auth Token : ", ex);
        }
    }
    
   

    private static List<QueryParameter> getQueryParameters(String user, String awsAccessKey, String dateStr, String dateTimeStr, String regionId, int expiryMinutes) {
        List<QueryParameter> qParams = new ArrayList<>();
        qParams.add(new QueryParameter("Action", ACTION));
        qParams.add(new QueryParameter("DBUser", UriUtils.uriEncode(user, true)));
        qParams.add(new QueryParameter(X_AMZ_ALGORITHM, AWS4_SIGNING_ALGORITHM));
        qParams.add(new QueryParameter(X_AMZ_DATE, dateTimeStr));
        qParams.add(new QueryParameter(X_AMZ_SIGNED_HEADER, SIGNED_HEADER));
        qParams.add(new QueryParameter(X_AMZ_EXPIRES, String.valueOf(expiryMinutes)));
        qParams.add(new QueryParameter(X_AMZ_CREDENTIAL, UriUtils.uriEncode(awsAccessKey + "/" + dateStr + "/" + regionId + "/" + SERVICE_NAME + "/" + AWS4_TERMINATOR, true)));
        return qParams;
    }
    
    private static String getQueryString0(List<QueryParameter> list) {
        StringBuilder sb = new StringBuilder();
        for (QueryParameter qp : list) {
            if (sb.length() > 0) {
                sb.append("&");
            }
            sb.append(qp.getKey());
            sb.append('=');
            sb.append(qp.getValue());
        }
        return sb.toString();
    }
    private static String getQueryString(List<QueryParameter> queryParameters) {
        return getQueryString0(queryParameters);
    }
    
    private static String getCanonicalQueryString(List<QueryParameter> queryParameters) {
        // Sort by the key name
        ArrayList<QueryParameter> newList = new ArrayList<>(queryParameters);
        Collections.sort(newList);
        return getQueryString0(newList);
    }

    private static String getCanonicalString(String canonicalQueryString, String hostName, int portNo) throws GeneralSecurityException {
        String canonicalHeaders = "host:" + hostName + ":" + portNo + LINE_SEPARATOR;
        return HTTP_METHOD + LINE_SEPARATOR + 
                CANONICAL_URI_RESOURCE + LINE_SEPARATOR + 
                canonicalQueryString + LINE_SEPARATOR + 
                canonicalHeaders + LINE_SEPARATOR + 
                SIGNED_HEADER + LINE_SEPARATOR + HEX_HASH;
    }

    //Step 2: Create a string to sign using sig v4
    private static String getStringToSign(String dateTimeStr, String canonicalRequest, String dateStr, String regionId) throws GeneralSecurityException  {
        String credentialScope = dateStr + "/" + regionId + "/" + SERVICE_NAME + "/" + AWS4_TERMINATOR;
        return AWS4_SIGNING_ALGORITHM + LINE_SEPARATOR 
                + dateTimeStr + LINE_SEPARATOR 
                + credentialScope + LINE_SEPARATOR 
                + HexUtils.bytesToHexStr(hash(canonicalRequest), Case.LOWER);
    }
  
    private static byte[] calculateSignature(String stringToSign,
            String awsSecretKey, 
            String dateStr, 
            String regionId) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(MAC_ALGORITHM);  // Optimization: re-use the same Mac
        byte[] signingKey = signingKey(mac, awsSecretKey, dateStr, regionId);
        return sign(mac, stringToSign, signingKey);
    }

    private static String getFinalToken0(String hostName, int portNo, String canonicalQueryString, String signature) {
        return hostName + ":" + portNo + "/?" + 
                canonicalQueryString + "&" + X_AMZ_SIGNATURE + "=" + signature;
    }

    private static byte[] sign(Mac mac, byte[] data, byte[] key) throws java.security.GeneralSecurityException {
        mac.init(new SecretKeySpec(key, MAC_ALGORITHM));
        return mac.doFinal(data);
    }

    private static byte[] sign(Mac mac, String stringData, byte[] key) throws GeneralSecurityException {
        byte[] data = stringData.getBytes(StandardCharsets.UTF_8);
        return sign(mac, data, key);
    }

    private static byte[] signingKey(
            Mac mac,
            String awsSecretKey,
            String dateStamp, 
            String regionName) throws GeneralSecurityException {
        // Optimization: There may be an opportunity here to cache
        // the signingKey. It doesn't change more often than 24h so at least
        // within the same day the same signingKey can be re-used.
        // However, it would mean caching the awsSecretKey. Which we don't want
        // to do for security reasons. 
        
        byte[] kSecret = ("AWS4" + awsSecretKey).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = sign(mac, dateStamp, kSecret);
        byte[] kRegion = sign(mac, regionName, kDate);
        byte[] kService = sign(mac, SERVICE_NAME, kRegion);
        return sign(mac, AWS4_TERMINATOR, kService);
    }
 
    private static byte[] hash(String s) throws java.security.GeneralSecurityException {
        // Optimization: There's an opportunity here to cache MessageDigest.
        // However, modern JDK is quite optimized with respect to MessageDigest creation
        // meaning that creating a new MessageDigest is nowadays almost as fast a 
        // re-using an existing MessageDigest.
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(s.getBytes(StandardCharsets.UTF_8));
        return md.digest();
    }





    private static class QueryParameter extends AbstractMap.SimpleImmutableEntry<String, String> implements Comparable<QueryParameter> {

        private static final long serialVersionUID = -5164521379249224514L;
        
        public QueryParameter(String key, String value) {
            super(key, value);
        }

        @Override
        public int compareTo(QueryParameter o) {
            return this.getKey().compareTo(o.getKey());
        }
    }
    
    /**
     * Input parameters for generating an RDS IAM Authentication Token.
     */
    public static class Parameters {
        private final String awsAccessKeyId;
        private final String awsSecretKey;
        private final String regionId;
        private final String hostname;
        private final int portNo;
        private final int expirySeconds;
        private final String dbUsername;
        private final Clock clock;
        private final RdsIamToken.Key tokenKey;

        private Parameters(String awsAccessKeyId, String awsSecretKey, String regionId, String hostname, int portNo, int expirySeconds, String dbUsername, Clock clock) {
            this.awsAccessKeyId = awsAccessKeyId;
            this.awsSecretKey = awsSecretKey;
            this.regionId = regionId;
            this.hostname = hostname;
            this.portNo = portNo;
            this.expirySeconds = expirySeconds;
            this.dbUsername = dbUsername;
            this.clock = clock;
            this.tokenKey = RdsIamToken.Key.builder()
                    .awsAccessKeyId(awsAccessKeyId)
                    .dbUsername(dbUsername)
                    .hostname(hostname)
                    .portNo(portNo)
                    .regionId(regionId)
                    .build();
        }

        public static Builder builder() {
            return new Builder();
        }
        
        public String getAwsAccessKeyId() {
            return awsAccessKeyId;
        }

        public String getAwsSecretKey() {
            return awsSecretKey;
        }

        public String getRegionId() {
            return regionId;
        }

        public String getHostname() {
            return hostname;
        }

        public int getPortNo() {
            return portNo;
        }

        public int getExpirySeconds() {
            return expirySeconds;
        }

        public String getDbUsername() {
            return dbUsername;
        }

        public Clock getClock() {
            return clock;
        }
        
        /**
         * Gets a key which is suitable for use in a Map when looking
         * up the token.
         * @return key
         */
        public RdsIamToken.Key getTokenKey() {
            return tokenKey;
        }
        
        /**
         * Builder for parameters.
         */
        public static class Builder {

            private String awsAccessKeyId;
            private String awsSecretKey;
            private String regionId;
            private String hostname;
            private Integer portNo;
            private int expirySeconds = 900;
            private String dbUsername;
            private Clock clock = Clock.systemUTC();

            private Builder() {
            }

            /**
             * Together with {@link #awsSecretKey(java.lang.String)} sets the
             * AWS credentials used in the signing process.
             *
             * <p>
             * MANDATORY.
             *
             * @param awsAccessKeyId
             * @return
             */
            public Builder awsAccessKeyId(String awsAccessKeyId) {
                this.awsAccessKeyId = awsAccessKeyId;
                return this;
            }

            /**
             * Together with {@link #awsAccessKeyId} sets the AWS credentials
             * used in the signing process.
             *
             * <p>
             * MANDATORY.
             *
             * @param awsSecretKey
             * @return
             */
            public Builder awsSecretKey(String awsSecretKey) {
                this.awsSecretKey = awsSecretKey;
                return this;
            }

            /**
             * Set the AWS Region Id of the endpoint, meaning the Region where
             * {@code hostname} is located. A Region Id is a string value which
             * uniquely identifies an AWS Region, such as {@code eu-central-1}
             * for the Frankfurt,Germany region or {@code us-east-2} for the
             * Ohio,USA region.
             *
             * <p>
             * This parameter is optional.
             * <ol>
             *    <li>Region derived from the {@code hostname} using the 
             *       {@link RegionUtils#getRegionIdFromHostname(java.lang.String)
             *        getRegionIdFromHostname() method}. (if method returns a non-empty
             *        value.)</li>
             *    <li>{@code aws.rds_region} system property.</li>
             *    <li>{@code AWS_RDS_REGION} environment variable.</li>
             * </ol>
             * 
             * <p>
             * If none of these methods succeeds a IllegalArgumentException will
             * be thrown at {@link #build() build time}. The resulting regionId
             * can be {@link Parameters#getRegionId() retrieved} from the
             * {@code Parameters} object after it has been
             * {@link #build() build}.
             *
             */
            public Builder regionId(String regionId) {
                this.regionId = regionId;
                return this;
            }

            /**
             * Set the hostname of the RDS instance. This must be the
             * {@code Address} element of an
             * <a href="https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_Endpoint.html">RDS
             * Endpoint</a>, it cannot be a DNS alias (CNAME record) or any 
             * any other proxy name.
             *
             * <p>
             * Example value:
             * {@code rdsmysql.123456789012.us-west-2.rds.amazonaws.com}.
             *
             * <p>
             * MANDATORY.
             *
             * @param hostname
             * @return
             */
            public Builder hostname(String hostname) {
                this.hostname = hostname;
                return this;
            }

            /**
             * Set the TCP port number where the RDS instance is running, for
             * example port 5432 for a PostgreSQL instance or port 3306 for a
             * MySQL instance.
             *
             * <p>
             * MANDATORY.
             *
             * @param portNo
             * @return
             */
            public Builder portNo(int portNo) {
                this.portNo = portNo;
                return this;
            }

            /**
             * Sets for how long the generated token should be valid, in
             * seconds. It hasn't been tested if the RDS service accepts tokens
             * with a longer time-to-live than the default of 15 minutes, so you
             * should probably not try to go above that. However, you can use a
             * smaller value for increased security. Recommend to leave this
             * value unset unless you have very good reason not to.
             *
             * <p>
             * OPTIONAL. If not set it will default to 900 seconds (15 minutes).
             *
             * @param expirySeconds
             * @return
             */
            public Builder expirySeconds(int expirySeconds) {
                this.expirySeconds = expirySeconds;
                return this;
            }

            /**
             * Set the DB username for which the IAM token should be obtained.
             * When creating a connection to the database server you would use
             * this value as the username and the generated token as the
             * password.
             *
             * <p>
             * MANDATORY.
             *
             * @param dbUsername
             * @return
             */
            public Builder dbUsername(String dbUsername) {
                this.dbUsername = dbUsername;
                return this;
            }

            /**
             * Sets the clock to use in the signing process. This is only
             * relevant for test scenarios.
             *
             * <p>
             * OPTIONAL. If not set the value defaults to
             * {@link Clock#systemUTC()} which is the default clock in the JDK.
             *
             * @param clock
             * @return
             */
            public Builder clock(Clock clock) {
                this.clock = clock;
                return this;
            }

            public RdsIamTokenGenerator.Parameters build() {
                Validation.validateNonNull(hostname, "hostname must be supplied");
                if (regionId == null) {
                    regionId = deriveRegionId();
                }
                Validation.validateNonNull(awsAccessKeyId, "awsAccessKeyId must be supplied");
                Validation.validateNonNull(awsSecretKey, "awsSecretKey must be supplied");
                Validation.validatePortNo(portNo);
                Validation.validateNonNull(dbUsername, "dbUsername must be supplied");
                return new RdsIamTokenGenerator.Parameters(awsAccessKeyId, awsSecretKey, regionId, hostname, portNo, expirySeconds, dbUsername, clock);
            }

            private String deriveRegionId() {

                Optional<String> regionIdFromHostname = RegionUtils.getRegionIdFromHostname(hostname);
                if (regionIdFromHostname.isPresent()) {
                    return regionIdFromHostname.get();
                }

                String regionIdFromSysProp = System.getProperty("aws.rds_region");
                if (regionIdFromSysProp != null) {
                    return regionIdFromSysProp;
                }
                String regionIdFromEnvVar = System.getenv("AWS_RDS_REGION");
                if (regionIdFromEnvVar != null) {
                    return regionIdFromEnvVar;
                }
                throw new IllegalArgumentException("Region was not set explicitly and cannot be determined from hosttname (\"" + hostname + "\") or from 'aws.rds_region' system property or from AWS_RDS_REGION environment variable.");
            }
        }
    }
}
