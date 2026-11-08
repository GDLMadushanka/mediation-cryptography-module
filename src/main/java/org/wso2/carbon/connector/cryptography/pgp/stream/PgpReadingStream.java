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

import org.apache.synapse.stream.StreamException;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPCryptoConstants;
import org.wso2.carbon.connector.cryptography.pgp.util.PGPKeyUtils;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

/**
 * Reads an OpenPGP message as a stream, decrypting it, verifying its signature, or both.
 *
 * <p>The mirror of {@link PgpMessageStream}, and one class for the same reason: the three shapes
 * differ only in which layers are present, and the walk through the packets is the part that is easy
 * to get subtly wrong.
 *
 * <h2>Verification is a verdict that arrives after the data</h2>
 * A one-pass signature puts its header before the literal data and its <b>signature after it</b>.
 * That layout is what lets a verifier hash while streaming — but it also means the verdict is only
 * available once the last byte has been read and handed on. The same is true of the modification
 * detection code, which is a trailer on the encrypted packet.
 *
 * <p>So this stream cannot refuse to produce bytes it has not yet verified. What it guarantees is
 * that nobody reaches the end of it without the check having run: the final {@code read()} — the one
 * that returns {@code -1} — is where verification happens, and it throws rather than returning.
 * Holding the data back until the verdict is known is {@link BarrierStream}'s job, one layer up,
 * because it is a policy about what the deployer's sequence can tolerate rather than a property of
 * OpenPGP.
 *
 * <p>A consumer that stops early never reaches the check at all. That is not a hole this class can
 * close — it is what streaming costs — and it is why the framework insists a failed run publishes
 * nothing.
 */
final class PgpReadingStream extends InputStream {

    private final InputStream upstream;
    private final String operator;
    private final PGPSecretKeyRingCollection secretKeys;
    private final String passphrase;
    private final boolean requireIntegrity;
    private final PGPPublicKeyRingCollection verificationKeys;
    private final boolean requireValidSignerKey;

    /** The factory that produced the literal data, kept so the trailing signature can be read. */
    private JcaPGPObjectFactory factory;
    private InputStream literal;
    private PGPPublicKeyEncryptedData encrypted;
    private PGPOnePassSignature onePass;

    private boolean opened;
    private boolean checked;

    /**
     * @param secretKeys       our private keys, or {@code null} when the message is not encrypted
     * @param verificationKeys the sender's public keys, or {@code null} to skip signature checking
     */
    PgpReadingStream(InputStream upstream, String operator, PGPSecretKeyRingCollection secretKeys,
                     String passphrase, boolean requireIntegrity,
                     PGPPublicKeyRingCollection verificationKeys, boolean requireValidSignerKey) {
        this.upstream = upstream;
        this.operator = operator;
        this.secretKeys = secretKeys;
        this.passphrase = passphrase;
        this.requireIntegrity = requireIntegrity;
        this.verificationKeys = verificationKeys;
        this.requireValidSignerKey = requireValidSignerKey;
    }

    /**
     * A failure a second attempt cannot fix, marked so the processor does not re-read a terabyte.
     *
     * <p>{@code StreamSequence} walks the cause chain and honours the first {@link StreamException}
     * it finds, ahead of anything it would guess from the exception type. Everything this class
     * refuses is a property of the message or the configuration — a signature does not become valid
     * by being read again, and neither does a missing key — so all of it says so. The default for an
     * unmarked {@code IOException} is retryable, which is right for a dropped connection and wrong
     * for every refusal here.
     */
    private IOException permanent(String message) {
        return new IOException(message, new StreamException(message, false));
    }

    @Override
    public int read() throws IOException {
        byte[] one = new byte[1];
        int n = read(one, 0, 1);
        return n == -1 ? -1 : one[0] & 0xFF;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (len == 0) {
            return 0;
        }
        if (!opened) {
            open();
        }
        int n = literal.read(b, off, len);
        if (n == -1) {
            check();
        } else if (onePass != null) {
            onePass.update(b, off, n);
        }
        return n;
    }

    /**
     * Unwraps whatever layers are present and stops at the literal data.
     *
     * <p>Done here rather than in {@code wrap()} because {@code wrap()} must perform no I/O
     * (invariant 1), and every step of this reads from the source.
     */
    private void open() throws IOException {
        try {
            // Handles both armored and binary input; the caller does not have to know which.
            JcaPGPObjectFactory current =
                    new JcaPGPObjectFactory(PGPUtil.getDecoderStream(upstream));
            if (secretKeys != null) {
                current = new JcaPGPObjectFactory(decrypt(current));
            }
            literal = walkToLiteralData(current);
            if (verificationKeys != null && onePass == null) {
                throw permanent(operator + " was asked to verify a signature but the message"
                        + " carries none. Either the sender did not sign it, or this stage should be"
                        + (secretKeys == null ? " a plain pass-through." : " pgpStreamDecrypt."));
            }
            opened = true;
        } catch (PGPException e) {
            throw new IOException(operator + " could not read the message: " + e.getMessage(), e);
        } catch (CryptoException e) {
            throw new IOException(operator + ": " + e.getMessage(), e);
        }
    }

    /** Finds the session key we hold and opens the clear stream behind it. */
    private InputStream decrypt(JcaPGPObjectFactory factory)
            throws IOException, PGPException, CryptoException {
        Object object = factory.nextObject();
        while (object != null && !(object instanceof PGPEncryptedDataList)) {
            object = factory.nextObject();
        }
        if (object == null) {
            throw permanent(operator + " found no encrypted data in the stream. It is not an"
                    + " OpenPGP message, or it is a signed-but-not-encrypted one.");
        }
        PGPEncryptedDataList list = (PGPEncryptedDataList) object;
        PGPPrivateKey privateKey = null;
        for (Iterator<?> it = list.getEncryptedDataObjects(); it.hasNext(); ) {
            PGPPublicKeyEncryptedData candidate = (PGPPublicKeyEncryptedData) it.next();
            PGPSecretKey secretKey = secretKeys.getSecretKey(candidate.getKeyIdentifier().getKeyId());
            if (secretKey != null) {
                privateKey = PGPKeyUtils.extractPrivateKey(secretKey, passphrase);
                encrypted = candidate;
                break;
            }
        }
        if (privateKey == null) {
            throw permanent(operator + " has no secret key that matches this message. It was"
                    + " encrypted to a different recipient, or the configured key store is not the"
                    + " one that goes with it.");
        }
        return encrypted.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider(PGPCryptoConstants.BC_PROVIDER)
                .build(privateKey));
    }

    /**
     * Walks past compression and a one-pass signature header to the literal data.
     *
     * <p>A loop rather than a fixed shape, because a message may be {@code compressed(literal)},
     * {@code literal} alone, or carry a one-pass signature header first, and all three are ordinary.
     * When this stage is verifying, the signature header is taken on the way past and primed with the
     * sender's key; when it is not, it is skipped exactly as before.
     */
    private InputStream walkToLiteralData(JcaPGPObjectFactory start)
            throws IOException, PGPException {
        JcaPGPObjectFactory current = start;
        for (int depth = 0; depth < 8; depth++) {
            Object object = current.nextObject();
            if (object == null) {
                throw permanent(operator + " found no data packet in the message");
            }
            if (object instanceof PGPLiteralData) {
                // Kept so check() can read the signature packet that follows the literal data.
                this.factory = current;
                return ((PGPLiteralData) object).getInputStream();
            }
            if (object instanceof PGPCompressedData) {
                current = new JcaPGPObjectFactory(((PGPCompressedData) object).getDataStream());
            } else if (object instanceof PGPOnePassSignatureList && verificationKeys != null) {
                primeSignature((PGPOnePassSignatureList) object);
            }
            // Anything else is passed over.
        }
        throw permanent(operator + " gave up looking for the data packet after eight layers of"
                + " nesting; the message is not one this operator can read");
    }

    private void primeSignature(PGPOnePassSignatureList signatures) throws IOException, PGPException {
        if (signatures.isEmpty()) {
            return;
        }
        PGPOnePassSignature candidate = signatures.get(0);
        PGPPublicKey signer = verificationKeys.getPublicKey(candidate.getKeyID());
        if (signer == null) {
            throw permanent(operator + " does not hold the public key of whoever signed this"
                    + " message (key ID " + Long.toHexString(candidate.getKeyID()) + "). Add that"
                    + " sender's key to the verification connection, or this signature cannot be"
                    + " checked at all.");
        }
        candidate.init(new JcaPGPContentVerifierBuilderProvider()
                .setProvider(PGPCryptoConstants.BC_PROVIDER), signer);
        onePass = candidate;
    }

    /**
     * Runs every check the message carries, once, at the end of the stream.
     *
     * <p>Signature first, then the modification detection code. The order is not arbitrary: a forged
     * signature is a statement about who sent the data, a failed MDC is a statement about whether it
     * arrived intact, and the first is the more serious thing to report when both are wrong.
     */
    private void check() throws IOException {
        if (checked) {
            return;
        }
        checked = true;
        try {
            if (onePass != null) {
                verifySignature();
            }
            if (encrypted != null) {
                verifyIntegrity();
            }
        } catch (PGPException e) {
            throw new IOException(operator + " could not complete its checks on the message: "
                    + e.getMessage(), e);
        } catch (CryptoException e) {
            throw new IOException(operator + ": " + e.getMessage(), e);
        }
    }

    private void verifySignature() throws IOException, PGPException, CryptoException {
        Object trailer = factory.nextObject();
        if (!(trailer instanceof PGPSignatureList) || ((PGPSignatureList) trailer).isEmpty()) {
            throw permanent(operator + " read the whole message but found no signature packet"
                    + " after the data. The message was truncated, or it was rewritten by something"
                    + " that dropped the signature.");
        }
        PGPSignature signature = ((PGPSignatureList) trailer).get(0);
        if (!onePass.verify(signature)) {
            throw permanent(operator + " read the whole message and its signature did NOT"
                    + " match. The data is not what the holder of that key signed — it was altered,"
                    + " or the signature was copied from another message. Nothing derived from this"
                    + " data may be trusted.");
        }
        if (requireValidSignerKey) {
            PGPKeyUtils.validateSignerKey(verificationKeys.getPublicKey(onePass.getKeyID()),
                    signature.getCreationTime());
        }
    }

    private void verifyIntegrity() throws IOException, PGPException {
        if (encrypted.isIntegrityProtected()) {
            if (!encrypted.verify()) {
                throw permanent(operator + " read the whole message and its integrity check"
                        + " failed. The ciphertext was altered in transit or at rest; the plaintext"
                        + " already produced must not be trusted.");
            }
        } else if (requireIntegrity) {
            throw permanent(operator + " refused a message with no modification detection"
                    + " code. Nothing would reveal tampering. Set requireIntegrity=false only for a"
                    + " sender that cannot produce one.");
        }
    }

    @Override
    public void close() throws IOException {
        if (literal != null) {
            literal.close();
        }
        upstream.close();
    }
}
