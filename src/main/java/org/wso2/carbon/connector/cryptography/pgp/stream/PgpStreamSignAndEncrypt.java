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
import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.pgp.connection.PgpKeyStore;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPParameterKey;
import org.wso2.integration.connector.core.AbstractConnector;
import org.wso2.integration.connector.core.ConnectException;

import java.io.InputStream;

/**
 * Signs a stream with our key and encrypts it to the recipient, in one pass.
 *
 * <pre>
 *   &lt;cryptography.pgpStreamSignAndEncrypt name="protect" configKey="partnerPublicKeys"&gt;
 *     &lt;signingConfigKey&gt;ourPrivateKeys&lt;/signingConfigKey&gt;
 *     &lt;resumeSecret&gt;{wso2:vault-lookup('mft.pgp.resumeSecret')}&lt;/resumeSecret&gt;
 *   &lt;/cryptography.pgpStreamSignAndEncrypt&gt;
 * </pre>
 *
 * <p>The outbound operator for partner traffic: the recipient can read it and can prove it came from
 * us. {@code configKey} is the recipient's public keys, exactly as on {@link PgpStreamEncrypt}, so
 * swapping one operator for the other leaves that attribute meaning the same thing;
 * {@code signingConfigKey} names our own private key connection.
 *
 * <h2>Why this is one operator and not two stages</h2>
 * The tempting composition — a signing stage feeding an encrypting one — is wrong, and wrong
 * quietly. An encrypting stage treats whatever it is handed as opaque bytes and wraps them in a
 * literal packet, so the result would be
 * {@code Encrypted(Compressed(Literal(OnePassSig, Literal(data), Sig)))} where the standard is
 * {@code Encrypted(Compressed(OnePassSig, Literal(data), Sig))}. A partner's PGP client decrypts the
 * first to something that looks like a PGP message rather than to the file. It is valid OpenPGP and
 * it is the wrong answer.
 *
 * <p>So the nesting is done in one place, by {@link PgpMessageStream}, where it can be got right
 * once.
 *
 * <h2>Capabilities</h2>
 * {@code deterministic()} only, on the same footing as {@link PgpStreamEncrypt}: a required
 * {@code resumeSecret} feeds {@link DerivedRandom}, which supplies the session key, the IV and the
 * signature nonce, and both timestamps are pinned.
 */
public class PgpStreamSignAndEncrypt extends AbstractConnector implements StreamTransform {

    static final String NAME = "cryptography.pgpStreamSignAndEncrypt";

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {
        throw new ConnectException(NAME + " is only valid inside a <streamSequence>. It signs and"
                + " wraps a byte stream rather than mediating a message; use pgp.signAndEncrypt in a"
                + " sequence.");
    }

    @Override
    public String name() {
        return NAME;
    }

    /** True for the reasons {@link PgpStreamEncrypt#deterministic()} gives, plus the signature nonce. */
    @Override
    public boolean deterministic() {
        return true;
    }

    @Override
    public InputStream wrap(InputStream upstream, StreamContext ctx) throws StreamException {
        // Captured now, while the template's parameters are still bound.
        MessageContext msg = ctx.message();
        try {
            PgpKeyStore recipient = PgpStreamSupport.store(NAME,
                    PgpStreamSupport.connectionName(msg, PGPParameterKey.ENCRYPTION_CONFIG_KEY),
                    false, "encrypting needs the recipient's public key store");
            PgpKeyStore ours = PgpStreamSupport.secondaryKeyStore(msg, NAME,
                    PgpStreamSupport.param(msg, PGPParameterKey.SIGNING_CONFIG_KEY), true,
                    PGPParameterKey.SIGNING_CONFIG_KEY,
                    "a signature is made with our own private key");
            return PgpStreamSign.signing(upstream, msg, ctx, ours, recipient, NAME);
        } catch (CryptoException e) {
            throw new StreamException(NAME + ": " + e.getMessage(), e, false);
        } catch (IllegalArgumentException e) {
            throw new StreamException(NAME + ": " + e.getMessage(), e, false);
        }
    }
}
