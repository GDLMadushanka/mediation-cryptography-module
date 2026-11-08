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
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.pgp.connection.PgpKeyStore;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPCryptoConstants;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPParameterKey;
import org.wso2.carbon.connector.cryptography.pgp.util.PGPKeyUtils;
import org.wso2.integration.connector.core.AbstractConnector;
import org.wso2.integration.connector.core.ConnectException;

import java.io.InputStream;

/**
 * Encrypts a stream to a recipient's public key as it passes, without holding it.
 *
 * <pre>
 *   &lt;cryptography.pgpStreamEncrypt name="encrypt" configKey="recipientKeys"&gt;
 *     &lt;resumeSecret&gt;{wso2:vault-lookup('mft.pgp.resumeSecret')}&lt;/resumeSecret&gt;
 *     &lt;symmetricKeyAlgorithm&gt;AES_256&lt;/symmetricKeyAlgorithm&gt;
 *   &lt;/cryptography.pgpStreamEncrypt&gt;
 * </pre>
 *
 * <p>The difference from {@code pgp.encrypt} is not the cryptography, it is the memory. That
 * operation reads the whole payload into a {@code byte[]} and returns another; this one holds a 64
 * KiB window and a cipher, so a 1 TB file costs the same heap as a 1 KB one.
 *
 * <h2>Why this operator needs a secret of its own</h2>
 * OpenPGP encryption is randomised, so encrypting a file twice normally gives two different files. A
 * transfer cannot live with that: a stage whose output changes between attempts cannot declare
 * {@code deterministic()}, and without that declaration no stage below it may keep a resume position
 * — so a crash at 400 GB restarts at zero. Worse, a framework that did not check would let the
 * destination keep its position and splice two different encryptions together into a file of exactly
 * the right length that will never decrypt.
 *
 * <p>So {@code resumeSecret} is required, and every random value the encryption needs is derived from
 * it and the run id rather than drawn fresh — see {@link DerivedRandom}, which carries the argument
 * for why that is not a weaker construction. Two runs never share a session key; one run resuming
 * always does.
 *
 * <p><b>The secret is key material.</b> It belongs in the secure vault, it must be the same on every
 * node that might resume the transfer, and changing it mid-transfer abandons that transfer's
 * checkpoint as surely as changing the input would.
 *
 * <h2>Compression is off by default here, and that is deliberate</h2>
 * {@code pgp.encrypt} defaults to ZLIB. Deflate output is deterministic for a given implementation
 * and level, but "a given implementation" is doing real work in that sentence: a run that resumed on
 * a node with a different JVM could produce different compressed bytes for the same records, and the
 * failure would look like data corruption rather than a configuration difference. Transfers are
 * usually of already-compressed data anyway. Set {@code compressionAlgorithm} if the saving is worth
 * pinning the runtime for.
 *
 * <h2>Capabilities</h2>
 * {@code deterministic()} only. Nothing durable is kept — the cipher state lives in the stream and
 * dies with it — so there is no workspace, no checkpoint and no artifact. A resumed run re-encrypts
 * from the beginning of whatever its upstream serves, and produces the same bytes it did before.
 *
 * @see PgpStreamSignAndEncrypt for the same thing with the sender's signature inside it
 */
public class PgpStreamEncrypt extends AbstractConnector implements StreamTransform {

    static final String NAME = "cryptography.pgpStreamEncrypt";

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {
        throw new ConnectException(NAME + " is only valid inside a <streamSequence>. It wraps a byte"
                + " stream in a cipher rather than mediating a message; use pgp.encrypt in a"
                + " sequence.");
    }

    @Override
    public String name() {
        return NAME;
    }

    /**
     * True, and only because {@code resumeSecret} makes it true.
     *
     * <p>Without the derived randomness of {@link DerivedRandom} this would have to be {@code false},
     * and a {@code false} here makes the operator unusable: every sink that moves bytes off this
     * machine declares {@code checkpointed()}, and the framework will not put one below a stage whose
     * output it cannot reproduce.
     */
    @Override
    public boolean deterministic() {
        return true;
    }

    @Override
    public InputStream wrap(InputStream upstream, StreamContext ctx) throws StreamException {
        // Captured now, while the template's parameters are still bound. The stream below is read
        // long after this method returns, when nothing is.
        MessageContext msg = ctx.message();
        try {
            PgpKeyStore store = PgpStreamSupport.store(NAME,
                    PgpStreamSupport.connectionName(msg, PGPParameterKey.ENCRYPTION_CONFIG_KEY),
                    false, "encrypting needs the recipient's public key store");
            PGPPublicKey recipient =
                    PGPKeyUtils.selectEncryptionKey(store.getPublicKeys(), store.getSelector());

            return new PgpMessageStream(upstream, NAME, recipient, null, null, 0,
                    PgpStreamCrypto.derivedRandom(msg, ctx, NAME),
                    PGPCryptoConstants.resolveSymmetricKeyAlgorithm(
                            PgpStreamSupport.param(msg, PGPParameterKey.SYMMETRIC_KEY_ALGORITHM,
                                    PGPCryptoConstants.DEFAULT_SYMMETRIC_ALGORITHM)),
                    compression(msg),
                    PgpStreamSupport.boolParam(msg, PGPParameterKey.ARMOR,
                            PGPCryptoConstants.DEFAULT_ARMOR),
                    PgpStreamSupport.boolParam(msg, PGPParameterKey.INTEGRITY_CHECK,
                            PGPCryptoConstants.DEFAULT_INTEGRITY_CHECK),
                    PgpStreamSupport.param(msg, PGPParameterKey.FILE_NAME, PGPLiteralData.CONSOLE));
        } catch (CryptoException e) {
            throw new StreamException(NAME + ": " + e.getMessage(), e, false);
        } catch (IllegalArgumentException e) {
            throw new StreamException(NAME + ": " + e.getMessage(), e, false);
        }
    }

    /** Unlike {@code pgp.encrypt}, off unless asked for. The class javadoc says why. */
    static int compression(MessageContext msg) {
        String configured = PgpStreamSupport.param(msg, PGPParameterKey.COMPRESSION_ALGORITHM);
        return configured == null
                ? CompressionAlgorithmTags.UNCOMPRESSED
                : PGPCryptoConstants.resolveCompressionAlgorithm(configured);
    }
}
