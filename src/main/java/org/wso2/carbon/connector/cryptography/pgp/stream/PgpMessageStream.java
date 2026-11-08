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

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPCryptoConstants;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

/**
 * Produces an OpenPGP message from a stream, signing it, encrypting it, or both.
 *
 * <p>One class rather than three because the packet layers nest, and the three shapes differ only in
 * which layers are present:
 *
 * <pre>
 *   encrypt only     Encrypted( Compressed( Literal(data) ) )
 *   sign only                   Compressed( OnePassSig, Literal(data), Sig )
 *   sign + encrypt   Encrypted( Compressed( OnePassSig, Literal(data), Sig ) )
 * </pre>
 *
 * <h2>Why sign-and-encrypt cannot be two sequence stages</h2>
 * The obvious composition — a signing stage feeding an encrypting one — produces
 * {@code Encrypted(Compressed(Literal(OnePassSig, Literal(data), Sig)))}, because an encrypting stage
 * treats whatever it is handed as opaque bytes and wraps them in a literal packet. A recipient
 * decrypts that to something that looks like a PGP message instead of the file. It is valid OpenPGP
 * and it is the wrong answer, which is the worst combination. So the two layers are applied here, in
 * one pass, where the nesting is ours to get right.
 *
 * <h2>Everything random is derived</h2>
 * The session key, its IV, and a DSA or ECDSA signature's nonce all come from the
 * {@link DerivedRandom} the caller supplies, and both timestamps that would otherwise be a clock
 * reading — the literal packet's and the signature's creation time — are pinned. Without all four the
 * stage could not declare {@code deterministic()}, and a transfer interrupted at 400 GB would start
 * again at zero. RSA signatures are deterministic anyway; the nonce matters only for DSA and ECDSA
 * keys, which is exactly the case nobody tests until a partner sends one.
 */
final class PgpMessageStream extends InputStream {

    /** Plaintext pulled per round trip through the generators. */
    private static final int CHUNK = 64 * 1024;

    /**
     * The timestamp written into the literal packet.
     *
     * <p>Pinned, because a clock reading is the one input a second attempt cannot reproduce. Nothing
     * reads it — it is metadata about the enclosed file, not about the message — so epoch costs
     * nothing. The signature's creation time is pinned differently; see {@link #signatureTime()}.
     */
    private static final Date PINNED_LITERAL_TIME = new Date(0L);

    private final InputStream upstream;
    private final String operator;
    private final PGPPublicKey recipient;
    private final PGPSecretKey signingKey;
    private final PGPPrivateKey signingPrivateKey;
    private final int hashAlgorithm;
    private final SecureRandom random;
    private final int symmetric;
    private final int compression;
    private final boolean armor;
    private final boolean integrity;
    private final String fileName;

    private final Collector collector = new Collector();
    private final byte[] chunk = new byte[CHUNK];

    private PGPEncryptedDataGenerator encryptedGenerator;
    private PGPCompressedDataGenerator compressedGenerator;
    private PGPLiteralDataGenerator literalGenerator;
    private PGPSignatureGenerator signatureGenerator;
    private ArmoredOutputStream armoredOut;
    private OutputStream compressedOut;
    private OutputStream literalOut;

    private boolean opened;
    private boolean closedGenerators;

    /**
     * @param recipient         the key to encrypt to, or {@code null} to produce an unencrypted
     *                          message
     * @param signingKey        the secret key to sign with, or {@code null} to produce an unsigned
     *                          message
     * @param signingPrivateKey the unlocked form of {@code signingKey}; ignored when it is null
     */
    PgpMessageStream(InputStream upstream, String operator, PGPPublicKey recipient,
                     PGPSecretKey signingKey, PGPPrivateKey signingPrivateKey, int hashAlgorithm,
                     SecureRandom random, int symmetric, int compression, boolean armor,
                     boolean integrity, String fileName) {
        this.upstream = upstream;
        this.operator = operator;
        this.recipient = recipient;
        this.signingKey = signingKey;
        this.signingPrivateKey = signingPrivateKey;
        this.hashAlgorithm = hashAlgorithm;
        this.random = random;
        this.symmetric = symmetric;
        this.compression = compression;
        this.armor = armor;
        this.integrity = integrity;
        this.fileName = fileName;
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
        // A `while`: a chunk of plaintext can disappear into a compressor's window and produce no
        // output at all, and returning 0 for a len > 0 request would spin the consumer.
        while (collector.available() == 0) {
            if (closedGenerators) {
                return -1;
            }
            if (!opened) {
                open();
                continue;
            }
            int n = upstream.read(chunk);
            if (n == -1) {
                // Closing is what writes the trailers: the literal packet's end, the signature, the
                // compressor's final block, the integrity packet. Skipping it produces a message that
                // decrypts and then fails verification, which reads as corruption.
                closeGenerators();
            } else {
                literalOut.write(chunk, 0, n);
                if (signatureGenerator != null) {
                    signatureGenerator.update(chunk, 0, n);
                }
            }
        }
        return collector.drain(b, off, len);
    }

    /** Builds the generator chain. Writes the packet headers into the collector, not to I/O. */
    private void open() throws IOException {
        try {
            OutputStream target = collector;
            if (armor) {
                armoredOut = new ArmoredOutputStream(collector);
                target = armoredOut;
            }
            if (recipient != null) {
                encryptedGenerator = new PGPEncryptedDataGenerator(
                        new JcePGPDataEncryptorBuilder(symmetric)
                                .setWithIntegrityPacket(integrity)
                                .setSecureRandom(random)
                                .setProvider(PGPCryptoConstants.BC_PROVIDER));
                encryptedGenerator.addMethod(
                        new JcePublicKeyKeyEncryptionMethodGenerator(recipient)
                                .setProvider(PGPCryptoConstants.BC_PROVIDER)
                                .setSecureRandom(random));
                target = encryptedGenerator.open(target, new byte[Collector.PACKET_BUFFER]);
            }
            compressedGenerator = new PGPCompressedDataGenerator(compression);
            compressedOut = compressedGenerator.open(target);

            if (signingKey != null) {
                signatureGenerator = new PGPSignatureGenerator(
                        new JcaPGPContentSignerBuilder(signingKey.getPublicKey().getAlgorithm(),
                                hashAlgorithm)
                                .setProvider(PGPCryptoConstants.BC_PROVIDER)
                                .setSecureRandom(random),
                        signingKey.getPublicKey());
                signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, signingPrivateKey);
                PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();
                subpackets.setSignatureCreationTime(false, signatureTime());
                signatureGenerator.setHashedSubpackets(subpackets.generate());
                // false: one signature, not nested inside another.
                signatureGenerator.generateOnePassVersion(false).encode(compressedOut);
            }

            literalGenerator = new PGPLiteralDataGenerator();
            literalOut = literalGenerator.open(compressedOut, PGPLiteralData.BINARY, fileName,
                    PINNED_LITERAL_TIME, new byte[Collector.PACKET_BUFFER]);
            opened = true;
        } catch (PGPException e) {
            throw new IOException(operator + " could not start writing the message: "
                    + e.getMessage(), e);
        }
    }

    /**
     * When this message claims to have been signed: the signing key's own creation time.
     *
     * <p>A real clock reading cannot be used — it is different on every attempt, and the signature is
     * part of the bytes a resumed transfer must reproduce. Epoch would be reproducible too, but a
     * partner's tooling would show every file as signed in 1970, and a verifier that applies key
     * expiry judges it against the signature's date. The key's creation time is stable, is always
     * within that key's own validity window, and reads sensibly at the other end.
     *
     * <p>What it costs is the one thing a signature timestamp is otherwise good for: this message
     * does not record when it was signed. The transfer's own audit trail records when it ran, which
     * is the question anyone actually asks.
     */
    private Date signatureTime() {
        return signingKey.getPublicKey().getCreationTime();
    }

    private void closeGenerators() throws IOException {
        try {
            literalGenerator.close();
            if (signatureGenerator != null) {
                // After the literal packet and before the compressor's trailer, which is where a
                // one-pass signature's own packet belongs.
                signatureGenerator.generate().encode(compressedOut);
            }
            compressedGenerator.close();
            if (encryptedGenerator != null) {
                encryptedGenerator.close();
            }
            if (armoredOut != null) {
                armoredOut.close();
            }
            closedGenerators = true;
        } catch (PGPException e) {
            throw new IOException(operator + " could not finish the message: " + e.getMessage(), e);
        }
    }

    @Override
    public void close() throws IOException {
        // Not closeGenerators(): a stream closed before its end is an abandoned run, and finishing
        // the message would hand the sink a complete, short file to commit.
        upstream.close();
    }
}
