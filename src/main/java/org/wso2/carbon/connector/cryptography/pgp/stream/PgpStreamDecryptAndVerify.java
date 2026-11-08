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
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPCryptoConstants;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPParameterKey;
import org.wso2.integration.connector.core.AbstractConnector;
import org.wso2.integration.connector.core.ConnectException;

import java.io.InputStream;

/**
 * Decrypts a stream and proves who sent it, holding the data back until it knows.
 *
 * <pre>
 *   &lt;cryptography.pgpStreamDecryptAndVerify name="open" configKey="ourPrivateKeys"&gt;
 *     &lt;verificationConfigKey&gt;partnerPublicKeys&lt;/verificationConfigKey&gt;
 *     &lt;mode&gt;strict&lt;/mode&gt;
 *   &lt;/cryptography.pgpStreamDecryptAndVerify&gt;
 * </pre>
 *
 * <p>The inbound operator for partner traffic: a file that fails this stage is a file nobody sent
 * you, whatever its contents claim.
 *
 * <h2>Why this cannot be two stages</h2>
 * In a signed-and-encrypted message the signature packets are <b>inside</b> the encryption, and a
 * decrypting stage must strip them to yield plaintext — so a verifying stage placed after one would
 * receive plaintext with nothing left to check. The two operations are fused here for the same
 * reason the packets are nested, not for convenience.
 *
 * <h2>Strict mode, and the hole it closes</h2>
 * A one-pass signature's verdict arrives after the data, so a verifying stream cannot refuse to emit
 * bytes it has not yet checked. The framework's own guarantee — a failed run publishes nothing —
 * covers the <i>sink</i>: a {@code .part} file is never renamed, a block list is never committed. It
 * does not cover a stage in between. A {@code forEach} that called an HTTP endpoint for every record
 * has already called it, and {@code abort()} cannot take that back.
 *
 * <p>So {@code mode=strict}, the default, drains the whole message into scratch before serving the
 * first byte — see {@link BarrierStream}. {@code mode=streaming} is the opt-out for a sequence that
 * only moves bytes into a sink publishing at commit, and it is the faster choice there because the
 * decrypt and the upload overlap again.
 *
 * <h2>Why not {@code materialises()}</h2>
 * It would not help and would actively break this. Framework materialisation serves downstream as it
 * writes, so it holds nothing back; and on a resumed run the framework serves the artifact's prefix
 * itself while the operator re-derives only the tail — so this stage would hash the tail alone and
 * check a whole-message signature against it. Materialisation and signature verification are
 * incompatible, which is why the barrier lives in the operator and uses {@code scratch()}, which is
 * ungated by capability flags for exactly this kind of working file.
 *
 * <h2>Capabilities</h2>
 * {@code deterministic()} only. Decryption is a function of its input, so a resumed run re-derives
 * the same plaintext; the verification is re-run from byte zero along with it, which is what keeps
 * the signature covering the whole message rather than a suffix of it.
 */
public class PgpStreamDecryptAndVerify extends AbstractConnector implements StreamTransform {

    static final String NAME = "cryptography.pgpStreamDecryptAndVerify";

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {
        throw new ConnectException(NAME + " is only valid inside a <streamSequence>. It unwraps and"
                + " checks a byte stream rather than mediating a message; use pgp.decryptAndVerify"
                + " in a sequence.");
    }

    @Override
    public String name() {
        return NAME;
    }

    /** Decryption is a function of its input, and verification adds nothing that varies. */
    @Override
    public boolean deterministic() {
        return true;
    }

    @Override
    public InputStream wrap(InputStream upstream, StreamContext ctx) throws StreamException {
        // Captured now, while the template's parameters are still bound.
        MessageContext msg = ctx.message();
        PgpKeyStore ours = PgpStreamSupport.store(NAME,
                PgpStreamSupport.connectionName(msg, PGPParameterKey.DECRYPTION_CONFIG_KEY),
                true, "decrypting needs our own private key store");
        PgpKeyStore theirs = PgpStreamSupport.secondaryKeyStore(msg, NAME,
                PgpStreamSupport.param(msg, PGPParameterKey.VERIFICATION_CONFIG_KEY), false,
                PGPParameterKey.VERIFICATION_CONFIG_KEY,
                "a signature is checked against the sender's public key");

        String override = PgpStreamSupport.param(msg, PGPParameterKey.PASSPHRASE);
        InputStream verifying = new PgpReadingStream(upstream, NAME, ours.getSecretKeys(),
                override == null ? ours.getPassphrase() : override,
                PgpStreamSupport.boolParam(msg, PGPParameterKey.REQUIRE_INTEGRITY,
                        PGPCryptoConstants.DEFAULT_REQUIRE_INTEGRITY),
                theirs.getPublicKeys(),
                PgpStreamSupport.boolParam(msg, PGPParameterKey.REQUIRE_VALID_SIGNER_KEY,
                        PGPCryptoConstants.DEFAULT_REQUIRE_VALID_SIGNER_KEY));
        return PgpStreamSupport.applyMode(verifying, NAME, msg, ctx);
    }
}
