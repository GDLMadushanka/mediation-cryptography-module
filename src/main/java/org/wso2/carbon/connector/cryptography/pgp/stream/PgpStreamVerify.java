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
 * Unwraps a signed — but not encrypted — stream, proving who sent it.
 *
 * <pre>
 *   &lt;cryptography.pgpStreamVerify name="check" configKey="partnerPublicKeys"/&gt;
 * </pre>
 *
 * <p>For the partner who signs for authenticity but does not encrypt, because the channel is already
 * private or the data is not confidential. {@link PgpStreamDecrypt} refuses such a message by name —
 * <i>"it is a signed-but-not-encrypted one"</i> — and this is what it should be pointed at instead.
 *
 * <p>Only one connection, so it arrives as the stage's {@code configKey} in the ordinary way. The
 * input is a signed message and the output is the data inside it, with the signature packets
 * removed.
 *
 * <h2>Everything {@link PgpStreamDecryptAndVerify} says about strict mode applies here</h2>
 * The verdict still arrives after the data, for the same reason — a one-pass signature puts its
 * signature packet after the literal data — so {@code mode=strict} is still the default and still
 * means the whole message is drained into scratch before any of it is served. The only difference is
 * that nothing had to be decrypted first, which makes the drain cheaper rather than different.
 *
 * <h2>Capabilities</h2>
 * {@code deterministic()} only. The output is a substring of the input; nothing here varies between
 * attempts.
 */
public class PgpStreamVerify extends AbstractConnector implements StreamTransform {

    static final String NAME = "cryptography.pgpStreamVerify";

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {
        throw new ConnectException(NAME + " is only valid inside a <streamSequence>. It checks a byte"
                + " stream rather than mediating a message; use pgp.verify in a sequence.");
    }

    @Override
    public String name() {
        return NAME;
    }

    /** The output is a substring of the input. Nothing here varies between attempts. */
    @Override
    public boolean deterministic() {
        return true;
    }

    @Override
    public InputStream wrap(InputStream upstream, StreamContext ctx) throws StreamException {
        // Captured now, while the template's parameters are still bound.
        MessageContext msg = ctx.message();
        PgpKeyStore theirs = PgpStreamSupport.store(NAME,
                PgpStreamSupport.connectionName(msg, PGPParameterKey.VERIFICATION_CONFIG_KEY),
                false, "verifying needs the sender's public key store");
        InputStream verifying = new PgpReadingStream(upstream, NAME, null, null, false,
                theirs.getPublicKeys(),
                PgpStreamSupport.boolParam(msg, PGPParameterKey.REQUIRE_VALID_SIGNER_KEY,
                        PGPCryptoConstants.DEFAULT_REQUIRE_VALID_SIGNER_KEY));
        return PgpStreamSupport.applyMode(verifying, NAME, msg, ctx);
    }
}
