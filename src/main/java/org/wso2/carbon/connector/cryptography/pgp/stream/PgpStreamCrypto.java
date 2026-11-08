/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.connector.cryptography.pgp.stream;

import org.apache.synapse.MessageContext;
import org.apache.synapse.stream.StreamContext;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * The resume secret, and the derived randomness every producing operator needs.
 *
 * <p>Shared by the three operators that write an OpenPGP message, because the argument for requiring
 * a secret is the same in all three and the label it is bound to must be built the same way. A label
 * that differed between two operators doing the same job would be a resume bug of the quiet kind:
 * both runs valid OpenPGP, neither resumable against the other.
 */
final class PgpStreamCrypto {

    /** The deployer's resume secret. Key material; vault it. */
    static final String RESUME_SECRET = "resumeSecret";

    private PgpStreamCrypto() {
    }

    /**
     * A {@link DerivedRandom} bound to this transfer and this stage.
     *
     * <p>The run id and the stage name, so two transfers never derive the same session key and one
     * transfer resuming always does. {@code jobId} is stable across attempts; nothing else available
     * here is.
     */
    static SecureRandom derivedRandom(MessageContext msg, StreamContext ctx, String operator) {
        byte[] secret = resumeSecret(msg, operator);
        String label = ctx.job().jobId() + "|" + ctx.stageName() + "|" + operator;
        return new DerivedRandom(secret, label);
    }

    private static byte[] resumeSecret(MessageContext msg, String operator) {
        String secret = PgpStreamSupport.param(msg, RESUME_SECRET);
        if (secret == null) {
            throw new IllegalArgumentException("a <resumeSecret> is required. It is what makes this"
                    + " stage's output reproducible, and without it a transfer that is interrupted"
                    + " must start again from the beginning. Put a random string of at least "
                    + DerivedRandom.MIN_SECRET_LENGTH + " characters in the secure vault and read it"
                    + " here; keep it the same on every node that may resume the transfer.");
        }
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < DerivedRandom.MIN_SECRET_LENGTH) {
            throw new IllegalArgumentException("<resumeSecret> is " + bytes.length + " bytes; it"
                    + " must be at least " + DerivedRandom.MIN_SECRET_LENGTH + ". It is key material,"
                    + " not a password — every random value " + operator + " uses is derived from"
                    + " it.");
        }
        return bytes;
    }
}
