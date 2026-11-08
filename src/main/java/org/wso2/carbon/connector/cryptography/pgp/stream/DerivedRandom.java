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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;

/**
 * The randomness an encryption draws, reproducible for one run and unpredictable to anyone else.
 *
 * <h2>Why a transfer needs this at all</h2>
 * OpenPGP encryption is randomised: a fresh session key and a fresh random prefix per message, which
 * is why encrypting the same file twice gives two different files. That is correct cryptography and
 * fatal to a resumable transfer. A stage that produces different bytes on its second attempt cannot
 * declare {@code deterministic()}, and without that no stage below it may keep a resume position —
 * so a crash at 400 GB would restart at zero, every time, and the framework would be right to insist.
 *
 * <p>Worse is what happens if nobody insists: the destination keeps its position, the re-encrypted
 * prefix is skipped over, and the file that lands is one message's first half with another's second.
 * It is exactly the right length. It will never decrypt.
 *
 * <p>So the randomness is <b>derived</b> rather than drawn. Every value the encryption needs comes
 * from {@code SHA-256(secret || label || counter)}, and a resumed attempt with the same secret and
 * the same label reproduces the same message byte for byte.
 *
 * <h2>Why this is not weaker than a random session key</h2>
 * The session key must be unpredictable <i>to an attacker</i>, not unpredictable in principle. It is
 * the output of SHA-256 over a secret the attacker does not have, which is the same construction as
 * any KDF. What it gives up is freshness against a <i>repeated</i> label, and that is the one thing
 * the label must therefore never be: it carries the run id, so two transfers never share a session
 * key, and the same transfer resuming always does.
 *
 * <p>Two rules fall out of that, and both are enforced by the operator rather than left to a comment:
 * the secret is required and must be long enough to be one, and the label always contains the run id.
 *
 * <h2>Scope</h2>
 * Deliberately a counter over a hash rather than a standards-named DRBG. It generates a few dozen
 * bytes per transfer — a session key and a packet prefix — so it needs to be obviously correct rather
 * than fast, and a reader should be able to confirm what it does in one sitting.
 */
public final class DerivedRandom extends SecureRandom {

    private static final long serialVersionUID = 1L;

    /** Shorter than this is a password, not a key, and would not survive being guessed at. */
    public static final int MIN_SECRET_LENGTH = 16;

    /**
     * @param secret the deployer's resume secret
     * @param label  what makes this stream unique — the run id, the stage, and what is being written
     */
    public DerivedRandom(byte[] secret, String label) {
        super(new CounterSpi(secret, label), null);
    }

    /** {@code SHA-256(secret || label || counter)}, concatenated. */
    private static final class CounterSpi extends SecureRandomSpi {

        private static final long serialVersionUID = 1L;

        private final byte[] secret;
        private final byte[] label;

        private long counter;
        private byte[] block = new byte[0];
        private int offset;

        private CounterSpi(byte[] secret, String label) {
            this.secret = secret.clone();
            this.label = label.getBytes(StandardCharsets.UTF_8);
        }

        /**
         * Ignored, on purpose.
         *
         * <p>Mixing in entropy from outside would make the stream unreproducible, which is the one
         * property this class exists to provide. Nothing on the encryption path calls it; if
         * something starts to, the failure to honour it is the safe direction.
         */
        @Override
        protected void engineSetSeed(byte[] ignored) {
        }

        @Override
        protected synchronized void engineNextBytes(byte[] bytes) {
            int written = 0;
            while (written < bytes.length) {
                if (offset >= block.length) {
                    block = next();
                    offset = 0;
                }
                int n = Math.min(bytes.length - written, block.length - offset);
                System.arraycopy(block, offset, bytes, written, n);
                offset += n;
                written += n;
            }
        }

        @Override
        protected byte[] engineGenerateSeed(int numBytes) {
            byte[] seed = new byte[numBytes];
            engineNextBytes(seed);
            return seed;
        }

        private byte[] next() {
            MessageDigest sha256;
            try {
                sha256 = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException impossible) {
                // Required of every JRE since 1.4.2.
                throw new IllegalStateException("SHA-256 is unavailable", impossible);
            }
            sha256.update(secret);
            sha256.update(label);
            long n = counter++;
            for (int shift = 56; shift >= 0; shift -= 8) {
                sha256.update((byte) (n >>> shift));
            }
            return sha256.digest();
        }
    }
}
