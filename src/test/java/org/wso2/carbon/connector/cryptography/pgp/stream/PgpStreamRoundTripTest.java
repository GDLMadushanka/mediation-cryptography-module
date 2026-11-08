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

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * The property the whole design rests on: producing the same message twice gives the same bytes.
 *
 * <p>Without it the producing operators could not declare {@code deterministic()}, no checkpointed
 * sink could sit below one, and an interrupted transfer would start again from zero. With it and no
 * test, the claim would be exactly the kind that is wrong silently — the output is a valid PGP
 * message either way, and only a resumed run would reveal otherwise.
 *
 * <p>Since signing was added the claim is larger: a DSA or ECDSA nonce and a signature's creation
 * time are both things that vary by default, so the signing paths are checked for reproducibility
 * too, not only the encrypting ones.
 */
public class PgpStreamRoundTripTest {

    private static final String PASSPHRASE = "test-passphrase";
    private static final String SECRET = "a-resume-secret-long-enough";
    private static final String OP = "test";

    private static PGPPublicKey publicKey;
    private static PGPPublicKeyRingCollection publicKeys;
    private static PGPSecretKeyRingCollection secretKeys;
    private static PGPSecretKey signingKey;
    private static PGPPrivateKey signingPrivateKey;

    @BeforeClass
    public static void generateAKeyPair() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        KeyPairGenerator rsa =
                KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        rsa.initialize(2048, new SecureRandom());
        PGPKeyPair pair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsa.generateKeyPair(),
                new Date());
        PGPKeyRingGenerator rings = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION, pair, "mft-test@wso2.com",
                new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1),
                null, null,
                new JcaPGPContentSignerBuilder(pair.getPublicKey().getAlgorithm(),
                        HashAlgorithmTags.SHA256),
                new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(PASSPHRASE.toCharArray()));
        publicKey = pair.getPublicKey();
        PGPSecretKeyRing secretRing = rings.generateSecretKeyRing();
        secretKeys = new PGPSecretKeyRingCollection(Collections.singletonList(secretRing));
        PGPPublicKeyRing publicRing = rings.generatePublicKeyRing();
        publicKeys = new PGPPublicKeyRingCollection(Collections.singletonList(publicRing));
        signingKey = secretRing.getSecretKey();
        signingPrivateKey = signingKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(PASSPHRASE.toCharArray()));
    }

    /** A plaintext long enough to cross the generators' internal buffers several times. */
    private static byte[] plaintext() {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < 20_000; i++) {
            text.append("row-").append(i).append(",some,fields,here\n");
        }
        return text.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static SecureRandom random(String label) {
        return new DerivedRandom(SECRET.getBytes(StandardCharsets.UTF_8), label);
    }

    /** One place for the long constructor, so each test reads as what it is actually asserting. */
    private static byte[] produce(byte[] plaintext, String label, boolean encrypt, boolean sign,
                                  int compression, boolean armor) throws Exception {
        return drain(new PgpMessageStream(new ByteArrayInputStream(plaintext), OP,
                encrypt ? publicKey : null,
                sign ? signingKey : null, sign ? signingPrivateKey : null, HashAlgorithmTags.SHA256,
                random(label), SymmetricKeyAlgorithmTags.AES_256, compression, armor, true,
                PGPLiteralData.CONSOLE));
    }

    private static byte[] consume(byte[] message, boolean decrypt, boolean verify) throws Exception {
        return drain(new PgpReadingStream(new ByteArrayInputStream(message), OP,
                decrypt ? secretKeys : null, decrypt ? PASSPHRASE : null, decrypt,
                verify ? publicKeys : null, true));
    }

    private static byte[] encrypt(byte[] plaintext, String label) throws Exception {
        return produce(plaintext, label, true, false, CompressionAlgorithmTags.UNCOMPRESSED, false);
    }

    private static byte[] decrypt(byte[] ciphertext) throws Exception {
        return consume(ciphertext, true, false);
    }

    private static byte[] drain(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int n;
        while ((n = in.read(chunk)) != -1) {
            out.write(chunk, 0, n);
        }
        return out.toByteArray();
    }

    // ---- encryption, unchanged behaviour -------------------------------------------------------

    @Test
    public void whatIsEncryptedCanBeDecrypted() throws Exception {
        byte[] plaintext = plaintext();
        assertArrayEquals(plaintext, decrypt(encrypt(plaintext, "run-1|encrypt")));
    }

    @Test
    public void theSameRunEncryptsToTheSameBytesTwice() throws Exception {
        // This is the resume case: the second attempt re-derives the prefix the first one wrote.
        byte[] plaintext = plaintext();
        assertArrayEquals("a resumed attempt must reproduce the earlier attempt's ciphertext",
                encrypt(plaintext, "run-1|encrypt"), encrypt(plaintext, "run-1|encrypt"));
    }

    @Test
    public void differentRunsEncryptToDifferentBytes() throws Exception {
        // The other half of the argument: determinism must not become session key reuse across
        // transfers. The label carries the run id, so two runs never share one.
        byte[] plaintext = plaintext();
        assertFalse("two runs must not produce the same ciphertext",
                Arrays.equals(encrypt(plaintext, "run-1|encrypt"),
                        encrypt(plaintext, "run-2|encrypt")));
    }

    @Test
    public void bothRunsStillDecryptToTheSamePlaintext() throws Exception {
        byte[] plaintext = plaintext();
        assertArrayEquals(plaintext, decrypt(encrypt(plaintext, "run-1|encrypt")));
        assertArrayEquals(plaintext, decrypt(encrypt(plaintext, "run-2|encrypt")));
    }

    @Test
    public void anEmptyStreamIsStillAValidMessage() throws Exception {
        byte[] empty = new byte[0];
        assertArrayEquals(empty, decrypt(encrypt(empty, "run-1|encrypt")));
    }

    @Test
    public void armouredOutputRoundTripsAndIsAlsoDeterministic() throws Exception {
        byte[] plaintext = "a short armoured message\n".getBytes(StandardCharsets.UTF_8);
        byte[] first = produce(plaintext, "run-1|encrypt", true, false,
                CompressionAlgorithmTags.UNCOMPRESSED, true);
        byte[] second = produce(plaintext, "run-1|encrypt", true, false,
                CompressionAlgorithmTags.UNCOMPRESSED, true);

        assertTrue("armoured output should be text",
                new String(first, StandardCharsets.US_ASCII).startsWith("-----BEGIN PGP MESSAGE"));
        assertArrayEquals(first, second);
        assertArrayEquals(plaintext, decrypt(first));
    }

    @Test
    public void compressionStillRoundTripsWhenAskedFor() throws Exception {
        byte[] plaintext = plaintext();
        byte[] ciphertext = produce(plaintext, "run-1|encrypt", true, false,
                CompressionAlgorithmTags.ZIP, false);
        assertTrue("compression should pay for itself on this input",
                ciphertext.length < plaintext.length);
        assertArrayEquals(plaintext, decrypt(ciphertext));
    }

    @Test
    public void alteredCiphertextIsCaughtByTheIntegrityCheck() throws Exception {
        byte[] ciphertext = encrypt(plaintext(), "run-1|encrypt");
        // Flip a bit well inside the encrypted packet, past the session key.
        ciphertext[ciphertext.length - 200] ^= 0x01;
        try {
            decrypt(ciphertext);
            fail("a tampered message should not read to the end cleanly");
        } catch (Exception expected) {
            assertTrue("expected an integrity complaint, got: " + expected.getMessage(),
                    expected.getMessage() != null);
        }
    }

    // ---- sign and verify, the unencrypted pair -------------------------------------------------

    @Test
    public void whatIsSignedCanBeVerified() throws Exception {
        byte[] plaintext = plaintext();
        byte[] signed = produce(plaintext, "run-1|sign", false, true,
                CompressionAlgorithmTags.UNCOMPRESSED, false);
        assertArrayEquals(plaintext, consume(signed, false, true));
    }

    @Test
    public void aSignedMessageIsAlsoReproducible() throws Exception {
        // The claim that matters for resume, and the one a DSA nonce or a clock reading would break.
        byte[] plaintext = plaintext();
        assertArrayEquals("a resumed attempt must reproduce the earlier attempt's signed message",
                produce(plaintext, "run-1|sign", false, true, CompressionAlgorithmTags.UNCOMPRESSED,
                        false),
                produce(plaintext, "run-1|sign", false, true, CompressionAlgorithmTags.UNCOMPRESSED,
                        false));
    }

    @Test
    public void alteringSignedDataIsCaught() throws Exception {
        byte[] signed = produce(plaintext(), "run-1|sign", false, true,
                CompressionAlgorithmTags.UNCOMPRESSED, false);
        // Well inside the literal data, away from the packet headers at either end.
        signed[signed.length / 2] ^= 0x01;
        try {
            consume(signed, false, true);
            fail("a message whose data was altered must not verify");
        } catch (Exception expected) {
            assertTrue("expected a signature complaint, got: " + expected.getMessage(),
                    expected.getMessage() != null && expected.getMessage().contains("signature"));
        }
    }

    @Test
    public void verifyingAnUnsignedMessageIsRefusedRatherThanPassed() throws Exception {
        // The failure that would matter most: a sender quietly stops signing and nobody notices.
        byte[] unsigned = produce(plaintext(), "run-1|encrypt", false, false,
                CompressionAlgorithmTags.UNCOMPRESSED, false);
        try {
            consume(unsigned, false, true);
            fail("an unsigned message must not pass a stage that was asked to verify");
        } catch (Exception expected) {
            assertTrue("expected a complaint about the missing signature, got: "
                            + expected.getMessage(),
                    expected.getMessage() != null && expected.getMessage().contains("carries none"));
        }
    }

    // ---- sign and encrypt, and the inbound pair ------------------------------------------------

    @Test
    public void whatIsSignedAndEncryptedCanBeDecryptedAndVerified() throws Exception {
        byte[] plaintext = plaintext();
        byte[] message = produce(plaintext, "run-1|protect", true, true,
                CompressionAlgorithmTags.UNCOMPRESSED, false);
        assertArrayEquals(plaintext, consume(message, true, true));
    }

    @Test
    public void aSignedAndEncryptedMessageIsAlsoReproducible() throws Exception {
        byte[] plaintext = plaintext();
        assertArrayEquals(
                produce(plaintext, "run-1|protect", true, true,
                        CompressionAlgorithmTags.UNCOMPRESSED, false),
                produce(plaintext, "run-1|protect", true, true,
                        CompressionAlgorithmTags.UNCOMPRESSED, false));
    }

    @Test
    public void aSignedAndEncryptedMessageStillDecryptsWithoutVerifying() throws Exception {
        // pgpStreamDecrypt skips the signature rather than tripping over it. A deployer who does not
        // ask for verification still gets their file.
        byte[] plaintext = plaintext();
        byte[] message = produce(plaintext, "run-1|protect", true, true,
                CompressionAlgorithmTags.UNCOMPRESSED, false);
        assertArrayEquals(plaintext, consume(message, true, false));
    }

    @Test
    public void signedAndEncryptedSurvivesCompressionToo() throws Exception {
        byte[] plaintext = plaintext();
        byte[] message = produce(plaintext, "run-1|protect", true, true,
                CompressionAlgorithmTags.ZIP, false);
        assertArrayEquals(plaintext, consume(message, true, true));
    }

    @Test
    public void tamperingWithSignedAndEncryptedDataIsCaught() throws Exception {
        byte[] message = produce(plaintext(), "run-1|protect", true, true,
                CompressionAlgorithmTags.UNCOMPRESSED, false);
        message[message.length - 200] ^= 0x01;
        try {
            consume(message, true, true);
            fail("a tampered signed-and-encrypted message must not read to the end cleanly");
        } catch (Exception expected) {
            assertTrue("expected a complaint, got: " + expected.getMessage(),
                    expected.getMessage() != null);
        }
    }

    @Test
    public void aFailedSignatureIsNotWorthRetrying() throws Exception {
        // A forged message does not become valid by being read again. Without this the processor
        // re-reads and re-drains the whole transfer up to five times before giving up, which at MFT
        // sizes is hours of bandwidth spent proving the same thing.
        byte[] signed = produce(plaintext(), "run-1|sign", false, true,
                CompressionAlgorithmTags.UNCOMPRESSED, false);
        signed[signed.length / 2] ^= 0x01;
        try {
            consume(signed, false, true);
            fail("an altered message must not verify");
        } catch (java.io.IOException expected) {
            org.apache.synapse.stream.StreamException verdict = null;
            for (Throwable t = expected; t != null; t = t.getCause()) {
                if (t instanceof org.apache.synapse.stream.StreamException streamException) {
                    verdict = streamException;
                    break;
                }
            }
            assertTrue("the failure must carry a verdict for StreamSequence to honour",
                    verdict != null);
            assertFalse("a bad signature must not be retried", verdict.isRetryable());
        }
    }

    @Test
    public void anEmptySignedMessageStillRoundTrips() throws Exception {
        byte[] empty = new byte[0];
        byte[] message = produce(empty, "run-1|protect", true, true,
                CompressionAlgorithmTags.UNCOMPRESSED, false);
        assertArrayEquals(empty, consume(message, true, true));
    }
}
