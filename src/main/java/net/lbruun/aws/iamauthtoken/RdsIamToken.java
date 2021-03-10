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
import java.time.Instant;
import java.util.Objects;

/**
 * Encapsulation of an RDS IAM Token.
 * 
 * <p>
 * The class encapsulates the {@link #getToken() token itself} as well as
 * the key attributes that went into creating the token, such as hostname,
 * dbUsername, etc, meaning the context in which the token can be used.
 * 
 * <p>
 * A token can be re-used for authentication until it expires as indicated
 * by the {@link #getExpirationTime() expiration time}. Remember to account
 * for differences in clock as well as network latency when figuring out 
 * if a token can still be used. For example, do not assume that a token
 * with only 2 msecs to expiry will still be accepted by the AWS RDS service.
 * 
 * <p>
 * The class implements {@link Comparable} so that objects can easily be ordered
 * based on their expiration time.
 * 
 * <p>
 * Instances of this class are immutable.
 * 
 * @author lbruun
 */
public class RdsIamToken implements Comparable<RdsIamToken> {

    private final String awsAccessKeyId;
    private final String regionId;
    private final String hostname;
    private final int portNo;
    private final String username;
    private final Instant expirationTime;
    private final String token;
    private final Key tokenKey;

    private RdsIamToken(String accessKeyId, String regionId, String hostname, int portNo, String username, Instant expirationTime, String token) {
        this.awsAccessKeyId = accessKeyId;
        this.regionId = regionId;
        this.hostname = hostname;
        this.portNo = portNo;
        this.username = username;
        this.expirationTime = expirationTime;
        this.token = token;
        
        tokenKey = Key.builder()
                .awsAccessKeyId(awsAccessKeyId)
                .dbUsername(username)
                .hostname(hostname)
                .portNo(portNo)
                .regionId(regionId)
                .build();
    }

    /**
     * Gets the AWS Access Key which was used to generate the token.
     */
    public String getAwsAccessKeyId() {
        return awsAccessKeyId;
    }

    
    /**
     * Gets signing Region. This is the region where
     * {@link #getHostname() hostname} is located.
     * 
     * <p>
     * A region id is a string, such as {@code "eu-central-1"} or
     * {@code "us-east-2"}, which uniquely identifies an AWS region.
     */
    public String getRegionId() {
        return regionId;
    }

    /**
     * Gets the hostname of the RDS endpoint.
     */
    public String getHostname() {
        return hostname;
    }

    /**
     * Gets the port of the RDS endpoint, typically port 5432 for a PostgreSQL 
     * instance or port 3306 for a MySQL instance. 
     */
    public int getPortNo() {
        return portNo;
    }

    /**
     * Gets the DB dbUsername.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Gets the time when the token expires.
     */
    public Instant getExpirationTime() {
        return expirationTime;
    }

    /**
     * Gets the IAM Auth Token. This is the value to be used
     * as DB password when authenticating against the RDS instance.
     */
    public String getToken() {
        return token;
    }
    
    /**
     * Gets a key for the token. The key may be useful when storing
     * generated tokens in a map.
     * @return 
     */
    public Key getTokenKey() {
        return tokenKey;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 79 * hash + Objects.hashCode(this.awsAccessKeyId);
        hash = 79 * hash + Objects.hashCode(this.regionId);
        hash = 79 * hash + Objects.hashCode(this.hostname);
        hash = 79 * hash + this.portNo;
        hash = 79 * hash + Objects.hashCode(this.username);
        hash = 79 * hash + Objects.hashCode(this.expirationTime);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final RdsIamToken other = (RdsIamToken) obj;
        if (this.portNo != other.portNo) {
            return false;
        }
        if (!Objects.equals(this.awsAccessKeyId, other.awsAccessKeyId)) {
            return false;
        }
        if (!Objects.equals(this.hostname, other.hostname)) {
            return false;
        }
        if (!Objects.equals(this.username, other.username)) {
            return false;
        }
        if (!Objects.equals(this.regionId, other.regionId)) {
            return false;
        }
        if (!Objects.equals(this.expirationTime, other.expirationTime)) {
            return false;
        }
        return true;
    }


    /**
     * Comparison based on object's {@code expirationTime} in ascending
     * order.
     * @param o
     * @return 
     */
    @Override
    public int compareTo(RdsIamToken o) {
        if (o == null) {
            return 1;
        }
        return this.getExpirationTime().compareTo(o.getExpirationTime());
    }

    
    
    
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Key is suitable for use as a key in a map storing objects
     * of type {@code RdsIamToken}.
     * 
     * <p>
     * The key is made up of:
     * <ul> 
     *   <li>{@code awsAccessKeyId}</li>
     *   <li>{@code hostname}</li>
     *   <li>{@code portNo}</li>
     *   <li>{@code regionId}</li>
     *   <li>{@code dbUsername}</li>
     * </ul>
     * 
     * <p>
     * Note that {@code expirationTime} is not part of the key. This makes it
     * possible to store multiple tokens for the same endpoint in a map, for
     * example a map defined as
     * {@code Map<RdsIamToken.Key, TreeSet<RdsIamToken>>}. In such a map, the
     * statement {@code map.get(key).last()} would return the token with
     * expiration time the furthest into the future.
     */
    public static class Key {
        private final String awsAccessKeyId;
        private final String regionId;
        private final String hostname;
        private final int portNo;
        private final String dbUsername;

        private Key(String awsAccessKeyId, String regionId, String hostname, int portNo, String dbUsername) {
            this.awsAccessKeyId = awsAccessKeyId;
            this.regionId = regionId;
            this.hostname = hostname;
            this.portNo = portNo;
            this.dbUsername = dbUsername;
        }

        public String getAwsAccessKeyId() {
            return awsAccessKeyId;
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

        public String getDbUsername() {
            return dbUsername;
        }
        
        @Override
        public int hashCode() {
            int hash = 7;
            hash = 89 * hash + Objects.hashCode(this.awsAccessKeyId);
            hash = 89 * hash + Objects.hashCode(this.regionId);
            hash = 89 * hash + Objects.hashCode(this.hostname);
            hash = 89 * hash + this.portNo;
            hash = 89 * hash + Objects.hashCode(this.dbUsername);
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final Key other = (Key) obj;
            if (this.portNo != other.portNo) {
                return false;
            }
            if (!Objects.equals(this.awsAccessKeyId, other.awsAccessKeyId)) {
                return false;
            }
            if (!Objects.equals(this.regionId, other.regionId)) {
                return false;
            }
            if (!Objects.equals(this.hostname, other.hostname)) {
                return false;
            }
            if (!Objects.equals(this.dbUsername, other.dbUsername)) {
                return false;
            }
            return true;
        }

        public static Key.Builder builder() {
            return new Key.Builder();
        }
        /**
         * Builder for Token Key.
         * 
         * <p>
         * All fields are required.
         */
        public static class Builder {

            private String awsAccessKeyId;
            private String regionId;
            private String hostname;
            private Integer portNo;
            private String dbUsername;

            private Builder() {
            }

            public Builder awsAccessKeyId(String awsAccessKeyId) {
                this.awsAccessKeyId = awsAccessKeyId;
                return this;
            }

            /**
             * Sets the region id of the RDS instance. Very often this can be
             * {@link net.lbruun.aws.iamauthtoken.utils.RegionUtils#getRegionIdFromHostname(java.lang.String)  safely derived}
             * from the hostname, however you must set the region id explicitly
             * here.
             *
             * @param regionId
             * @return 
             */
            public Builder regionId(String regionId) {
                this.regionId = regionId;
                return this;
            }

            public Builder hostname(String hostname) {
                this.hostname = hostname;
                return this;
            }

            public Builder portNo(int portNo) {
                this.portNo = portNo;
                return this;
            }

            public Builder dbUsername(String dbUsername) {
                this.dbUsername = dbUsername;
                return this;
            }
            
            /**
             * Builds the key. 
             * @throws IllegalArgumentException if not all fields have been set
             * @return 
             */
            public Key build() {
                Validation.validateNonNull(awsAccessKeyId, "awsAccessKeyId cannot be null");
                Validation.validateNonNull(regionId, "regionId cannot be null");
                Validation.validateNonNull(hostname, "hostname cannot be null");
                Validation.validatePortNo(portNo);
                Validation.validateNonNull(dbUsername, "dbUsername cannot be null");
                return new Key(awsAccessKeyId, regionId, hostname, 0, dbUsername);
            }
        }
    }

    /**
     * Builder for a Token.
     * You'll rarely have to use this. The {@link RdsIamTokenGenerator Generator}
     * generates these objects for you.
     */
    public static class Builder {

        private String awsAccessKeyId;
        private String regionId;
        private String hostname;
        private int portNo;
        private String dbUsername;
        private Instant expirationTime;
        private String token;

        private Builder() {
        }

        public Builder awsAccessKeyId(String accessKeyId) {
            this.awsAccessKeyId = accessKeyId;
            return this;
        }

        public Builder regionId(String regionId) {
            this.regionId = regionId;
            return this;
        }

        public Builder hostname(String hostname) {
            this.hostname = hostname;
            return this;
        }

        public Builder portNo(int portNo) {
            this.portNo = portNo;
            return this;
        }

        public Builder dbUsername(String dbUsername) {
            this.dbUsername = dbUsername;
            return this;
        }

        public Builder expirationTime(Instant expirationTime) {
            this.expirationTime = expirationTime;
            return this;
        }
        
        public Builder token(String token) {
            this.token = token;
            return this;
        }

        public RdsIamToken build() {
            return new RdsIamToken(awsAccessKeyId, regionId, hostname, portNo, dbUsername, expirationTime, token);
        }
    }
}
