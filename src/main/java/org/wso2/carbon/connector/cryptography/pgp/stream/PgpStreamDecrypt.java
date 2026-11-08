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
import org.apache.synapse.stream.StreamException;
import org.apache.synapse.stream.StreamTransform;
import org.wso2.carbon.connector.cryptography.pgp.connection.PgpKeyStore;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPParameterKey;
import org.wso2.integration.connector.core.AbstractConnector;
import org.wso2.integration.connector.core.ConnectException;

import java.io.InputStream;

/**
 * Decrypts an OpenPGP stream as it passes, without holding it.
 *
 * <pre>
 *   &lt;cryptography.pgpStreamDecrypt name="decrypt" configKey="ourPrivateKeys"/&gt;
 * </pre>
 *
 * <p>The easy direction. OpenPGP's packet layout is a stream to begin with, so Bouncy Castle hands
 * back a plain {@code InputStream} once the session key is unwrapped, and this operator is mostly the
 * unwrapping — no buffering, no bridge between push and pull, no secret of its own.
 *
 * <h2>This operator does not check signatures</h2>
 * If the message was signed as well as encrypted, the signature is <b>skipped</b>, not checked and
 * not reported. That is a deliberate split rather than an omission: checking it changes what the
 * stage can promise and what it costs, so it is a different operator — {@link PgpStreamDecryptAndVerify}
 * — and which one appears in the sequence is then a visible, auditable fact rather than an attribute
 * someone may or may not have set.
 *
 * <p>Use this one when the sender does not sign, or when authenticity is established some other way.
 * Use the other when a forged file must not be acted on.
 *
 * <h2>Deterministic without doing anything for it</h2>
 * Decryption is a function: the same ciphertext always yields the same plaintext. That makes this
 * stage resumable in a way {@link PgpStreamEncrypt} has to work for, and it is why a
 * <b>download-and-decrypt sequence resumes cleanly today</b> while an encrypt-and-upload one needs
 * {@code resumeSecret}.
 *
 * <h2>The integrity check runs at the end, and must</h2>
 * The modification detection code sits in a trailer after the ciphertext, so it can only be verified
 * once the last byte has been read. A consumer that stops early never reaches it. That is not a hole
 * this operator can close — it is what streaming costs — but the common case in a transfer is that
 * the sink reads to the end, and then a tampered message fails the stage rather than being written.
 *
 * <p>When the verification does fail the bytes are already downstream. For a sink that holds its
 * output until commit, as every MFT sink does, that is harmless: the run fails and nothing is
 * published. For anything that publishes as it goes it would not be, which is one more reason the
 * framework insists a failed run publishes nothing — and why {@link PgpStreamDecryptAndVerify} offers
 * a strict mode that holds the data back instead.
 *
 * <h2>Capabilities</h2>
 * {@code deterministic()} only. No workspace, no checkpoint, nothing durable.
 */
public class PgpStreamDecrypt extends AbstractConnector implements StreamTransform {

    static final String NAME = "cryptography.pgpStreamDecrypt";

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {
        throw new ConnectException(NAME + " is only valid inside a <streamSequence>. It unwraps a byte"
                + " stream rather than mediating a message; use pgp.decrypt in a sequence.");
    }

    @Override
    public String name() {
        return NAME;
    }

    /** Decryption is a function of its input. Nothing here varies between attempts. */
    @Override
    public boolean deterministic() {
        return true;
    }

    @Override
    public InputStream wrap(InputStream upstream, StreamContext ctx) throws StreamException {
        // Captured now, while the template's parameters are still bound.
        MessageContext msg = ctx.message();
        PgpKeyStore store = PgpStreamSupport.store(NAME,
                PgpStreamSupport.connectionName(msg, PGPParameterKey.DECRYPTION_CONFIG_KEY),
                true, "decrypting needs our own private key store");
        String override = PgpStreamSupport.param(msg, PGPParameterKey.PASSPHRASE);
        return new PgpReadingStream(upstream, NAME, store.getSecretKeys(),
                override == null ? store.getPassphrase() : override,
                PgpStreamSupport.boolParam(msg, PGPParameterKey.REQUIRE_INTEGRITY, true),
                null, false);
    }
}
