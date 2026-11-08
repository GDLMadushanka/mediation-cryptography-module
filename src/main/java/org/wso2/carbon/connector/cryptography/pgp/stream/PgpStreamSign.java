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
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.pgp.connection.PgpKeyStore;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPCryptoConstants;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPParameterKey;
import org.wso2.carbon.connector.cryptography.pgp.util.PGPKeyUtils;
import org.wso2.integration.connector.core.AbstractConnector;
import org.wso2.integration.connector.core.ConnectException;

import java.io.InputStream;

/**
 * Signs a stream as it passes, without encrypting it.
 *
 * <pre>
 *   &lt;cryptography.pgpStreamSign name="sign" configKey="ourPrivateKeys"&gt;
 *     &lt;resumeSecret&gt;{wso2:vault-lookup('mft.pgp.resumeSecret')}&lt;/resumeSecret&gt;
 *   &lt;/cryptography.pgpStreamSign&gt;
 * </pre>
 *
 * <p>The producing half of the signed-but-not-encrypted flow {@link PgpStreamVerify} reads. For a
 * partner who needs to know the file came from you, over a channel that already keeps it private.
 *
 * <h2>Signing streams; verifying cannot</h2>
 * A one-pass signature exists precisely so a signer can hash while writing and emit the signature
 * packet at the end, so this operator holds nothing back and needs no workspace — unlike its
 * inbound counterpart, where the verdict arrives after the data and the data must be held until it
 * does. The asymmetry is real and worth remembering: outbound the signature is something you
 * produce at the end, inbound it is a verdict that arrives after the bytes are already gone.
 *
 * <h2>Why this needs a resumeSecret too</h2>
 * An RSA signature is deterministic, but a DSA or ECDSA one draws a random nonce and would differ on
 * every attempt — which would make the stage's output irreproducible and so unresumable, exactly as
 * an unseeded encryption would. The nonce therefore comes from {@link DerivedRandom} like every
 * other random value in this package. The signature's creation time is pinned as well; see
 * {@link PgpMessageStream} for what that costs and why.
 *
 * <h2>Capabilities</h2>
 * {@code deterministic()} only, and only because of the above.
 */
public class PgpStreamSign extends AbstractConnector implements StreamTransform {

    static final String NAME = "cryptography.pgpStreamSign";

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {
        throw new ConnectException(NAME + " is only valid inside a <streamSequence>. It signs a byte"
                + " stream rather than mediating a message; use pgp.sign in a sequence.");
    }

    @Override
    public String name() {
        return NAME;
    }

    /** True, and only because the signature nonce and timestamp are both derived rather than drawn. */
    @Override
    public boolean deterministic() {
        return true;
    }

    @Override
    public InputStream wrap(InputStream upstream, StreamContext ctx) throws StreamException {
        // Captured now, while the template's parameters are still bound.
        MessageContext msg = ctx.message();
        try {
            PgpKeyStore ours = PgpStreamSupport.store(NAME,
                    PgpStreamSupport.connectionName(msg, PGPParameterKey.SIGNING_CONFIG_KEY),
                    true, "signing needs our own private key store");
            return signing(upstream, msg, ctx, ours, null, NAME);
        } catch (CryptoException e) {
            throw new StreamException(NAME + ": " + e.getMessage(), e, false);
        } catch (IllegalArgumentException e) {
            throw new StreamException(NAME + ": " + e.getMessage(), e, false);
        }
    }

    /**
     * Builds the signing stream, optionally wrapping the result in encryption.
     *
     * <p>Shared with {@link PgpStreamSignAndEncrypt}, which differs only in passing a recipient.
     *
     * @param recipientStore the recipient's public keys, or {@code null} to sign without encrypting
     */
    static InputStream signing(InputStream upstream, MessageContext msg, StreamContext ctx,
                               PgpKeyStore signingStore, PgpKeyStore recipientStore, String operator)
            throws CryptoException, StreamException {
        PGPSecretKey signingKey =
                PGPKeyUtils.findSigningSecretKey(signingStore.getSecretKeys(), signingStore.getSelector());
        String override = PgpStreamSupport.param(msg, PGPParameterKey.PASSPHRASE);
        String passphrase = override == null ? signingStore.getPassphrase() : override;
        return new PgpMessageStream(upstream, operator,
                recipientStore == null
                        ? null
                        : PGPKeyUtils.selectEncryptionKey(recipientStore.getPublicKeys(),
                                recipientStore.getSelector()),
                signingKey, PGPKeyUtils.extractPrivateKey(signingKey, passphrase),
                PGPCryptoConstants.resolveHashAlgorithm(
                        PgpStreamSupport.param(msg, PGPParameterKey.SIGNATURE_HASH_ALGORITHM,
                                PGPCryptoConstants.DEFAULT_HASH_ALGORITHM)),
                PgpStreamCrypto.derivedRandom(msg, ctx, operator),
                PGPCryptoConstants.resolveSymmetricKeyAlgorithm(
                        PgpStreamSupport.param(msg, PGPParameterKey.SYMMETRIC_KEY_ALGORITHM,
                                PGPCryptoConstants.DEFAULT_SYMMETRIC_ALGORITHM)),
                PgpStreamEncrypt.compression(msg),
                PgpStreamSupport.boolParam(msg, PGPParameterKey.ARMOR,
                        PGPCryptoConstants.DEFAULT_ARMOR),
                PgpStreamSupport.boolParam(msg, PGPParameterKey.INTEGRITY_CHECK,
                        PGPCryptoConstants.DEFAULT_INTEGRITY_CHECK),
                PgpStreamSupport.param(msg, PGPParameterKey.FILE_NAME, PGPLiteralData.CONSOLE));
    }
}
