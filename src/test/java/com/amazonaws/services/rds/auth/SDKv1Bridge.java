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
package com.amazonaws.services.rds.auth;

import com.amazonaws.auth.presign.PresignerParams;

/**
 * Exists because we need to use a package-private constructor 
 * on the 'RdsIamAuthTokenGenerator' class from AWS SDK v1.
 * This allows us to set the Clock which is being used.
 * 
 * @author lbruun
 */
public class SDKv1Bridge {

    private SDKv1Bridge() {
    }
    
    public static RdsIamAuthTokenGenerator getGenerator(PresignerParams presignerParams) {
        // Using package private constructor here so need to be in same package
        return new RdsIamAuthTokenGenerator(presignerParams);
    }
}
