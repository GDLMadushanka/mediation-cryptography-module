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
package org.wso2.carbon.connector.cryptography.pgp.util;

import org.apache.synapse.MessageContext;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.wso2.carbon.connector.cryptography.exception.CryptoError;
import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPCryptoConstants;
import org.wso2.carbon.connector.cryptography.pgp.model.KeySelector;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Iterator;

/**
 * Loads OpenPGP public and secret key-ring collections from any supported source
 * ({@linkplain KeySourceResolver registry / environment / inline / filesystem}) and selects a key
 * from a ring by a strict {@link KeySelector} (fingerprint or 64-bit Key ID).
 *
 * <p><b>Parsing happens once.</b> The key rings are parsed at connection-init time and the resulting
 * immutable collections are held on the {@code PgpKeyStore} connection for the operations to reuse,
 * so there is no per-message re-parse to cache against.</p>
 *
 * <p><b>Selection.</b> Only exact cryptographic selectors are honoured — a full-fingerprint byte
 * comparison or an exact 64-bit Key ID lookup. Free-text user-ID/e-mail substring matching has been
 * removed. A fingerprint or Key ID may target a certificate's primary key; when that key lacks the
 * required capability (encryption is typically on a subkey), resolution falls back to the matching
 * capability key within the same certificate.</p>
 *
 * <p>All methods are static and hold no shared state; the Bouncy Castle collections they return are
 * read-only and safe to share across mediation threads.</p>
 */
public final class PGPKeyUtils {

    private PGPKeyUtils() {
    }

    /**
     * Parse the full public key-ring collection. Called once at connection-init time; the parsed
     * collection is then held on the connection and reused by verification (which discovers the
     * signer's key ID from the signature itself) and by {@link #selectEncryptionKey}.
     */
    public static PGPPublicKeyRingCollection loadPublicKeyRingCollection(MessageContext mc, String source)
            throws CryptoException {
        try (InputStream in = openDecoded(mc, source)) {
            return new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());
        } catch (IOException | PGPException e) {
            throw new CryptoException(CryptoError.KEY_LOAD_ERROR,
                    "Failed to load public key-ring from: " + describeSource(source), e);
        }
    }

    /**
     * Parse the secret key-ring collection. Called once at connection-init time.
     */
    public static PGPSecretKeyRingCollection loadSecretKeyRingCollection(MessageContext mc, String source)
            throws CryptoException {
        try (InputStream in = openDecoded(mc, source)) {
            return new PGPSecretKeyRingCollection(in, new JcaKeyFingerprintCalculator());
        } catch (IOException | PGPException e) {
            throw new CryptoException(CryptoError.KEY_LOAD_ERROR,
                    "Failed to load secret key-ring from: " + describeSource(source), e);
        }
    }

    /**
     * Resolve the key location to raw bytes (registry / env / inline / file) and wrap them in an
     * OpenPGP decoder stream, which transparently handles both ASCII-armored and binary key material.
     */
    private static InputStream openDecoded(MessageContext mc, String source) throws CryptoException, IOException {
        byte[] raw = KeySourceResolver.read(mc, source);
        return PGPUtil.getDecoderStream(new ByteArrayInputStream(raw));
    }

    /**
     * Select an encryption-capable public key from an already-parsed collection using the selector
     * (fingerprint, Key ID, or exact user ID / e-mail). Used by the connection-based operations,
     * where the public key-ring collection is resolved and parsed once at connection-init time.
     *
     * <p>A revoked or expired key is never returned; if the matched certificate's only
     * encryption-capable key is revoked/expired, {@link CryptoError#KEY_UNUSABLE} is raised.</p>
     *
     * @param rings    a public key-ring collection held on a public key store connection.
     * @param selector the recipient selector; must carry a fingerprint, Key ID, or user ID.
     */
    public static PGPPublicKey selectEncryptionKey(PGPPublicKeyRingCollection rings, KeySelector selector)
            throws CryptoException {
        selector.requireStrictSelector();
        PGPPublicKeyRing ring = findPublicRing(rings, selector);
        PGPPublicKey key = pickEncryptionKey(ring, selector);
        if (key == null) {
            throw new CryptoException(CryptoError.KEY_NOT_FOUND,
                    "Certificate for " + selector.describe() + " has no encryption-capable key.");
        }
        return key;
    }

    /**
     * Locate a signing-capable secret key using the selector (fingerprint, Key ID, or exact
     * user ID / e-mail). A revoked or expired key is never returned.
     */
    public static PGPSecretKey findSigningSecretKey(PGPSecretKeyRingCollection secretKeys, KeySelector selector)
            throws CryptoException {
        selector.requireStrictSelector();
        PGPSecretKeyRing ring = findSecretRing(secretKeys, selector);
        PGPSecretKey key = pickSigningKey(ring, selector);
        if (key == null) {
            throw new CryptoException(CryptoError.KEY_NOT_FOUND,
                    "Certificate for " + selector.describe() + " has no signing-capable key.");
        }
        return key;
    }

    /**
     * Extract the decrypted private key from a secret key using the passphrase.
     */
    public static PGPPrivateKey extractPrivateKey(PGPSecretKey secretKey, String passphrase)
            throws CryptoException {
        if (secretKey == null) {
            throw new CryptoException(CryptoError.KEY_NOT_FOUND, "Secret key is null; cannot extract private key.");
        }
        try {
            char[] pass = passphrase == null ? new char[0] : passphrase.toCharArray();
            return secretKey.extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder()
                            .setProvider(PGPCryptoConstants.BC_PROVIDER)
                            .build(pass));
        } catch (PGPException e) {
            throw new CryptoException(CryptoError.INVALID_PASSPHRASE,
                    "Failed to extract private key (wrong passphrase or key ID?).", e);
        }
    }

    //  Ring lookup by selector

    /** Locate the public key ring matching the selector (fingerprint, Key ID, or exact user ID). */
    private static PGPPublicKeyRing findPublicRing(PGPPublicKeyRingCollection rings, KeySelector selector)
            throws CryptoException {
        PGPPublicKeyRing ring;
        byte[] fp = parseFingerprintOrNull(selector.getFingerprint());
        if (fp != null) {
            ring = rings.getPublicKeyRing(fp);
        } else if (selector.getKeyId() != null) {
            ring = rings.getPublicKeyRing(parseKeyId(selector.getKeyId()));
        } else {
            ring = findPublicRingByUserId(rings, selector.getUserId());
        }
        if (ring == null) {
            throw new CryptoException(CryptoError.KEY_NOT_FOUND,
                    "No public key found matching " + selector.describe() + ".");
        }
        return ring;
    }

    /** Locate the secret key ring matching the selector (fingerprint, Key ID, or exact user ID). */
    private static PGPSecretKeyRing findSecretRing(PGPSecretKeyRingCollection secretKeys, KeySelector selector)
            throws CryptoException {
        PGPSecretKeyRing ring;
        byte[] fp = parseFingerprintOrNull(selector.getFingerprint());
        if (fp != null) {
            ring = findSecretRingByFingerprint(secretKeys, fp);
        } else if (selector.getKeyId() != null) {
            ring = secretKeys.getSecretKeyRing(parseKeyId(selector.getKeyId()));
        } else {
            ring = findSecretRingByUserId(secretKeys, selector.getUserId());
        }
        if (ring == null) {
            throw new CryptoException(CryptoError.KEY_NOT_FOUND,
                    "No secret key found matching " + selector.describe() + ".");
        }
        return ring;
    }

    private static PGPPublicKeyRing findPublicRingByUserId(PGPPublicKeyRingCollection rings, String userId) {
        for (Iterator<PGPPublicKeyRing> it = rings.getKeyRings(); it.hasNext(); ) {
            PGPPublicKeyRing ring = it.next();
            for (Iterator<PGPPublicKey> keyIt = ring.getPublicKeys(); keyIt.hasNext(); ) {
                if (keyMatchesUserId(keyIt.next(), userId)) {
                    return ring;
                }
            }
        }
        return null;
    }

    private static PGPSecretKeyRing findSecretRingByUserId(PGPSecretKeyRingCollection secretKeys, String userId) {
        for (Iterator<PGPSecretKeyRing> ringIt = secretKeys.getKeyRings(); ringIt.hasNext(); ) {
            PGPSecretKeyRing ring = ringIt.next();
            for (Iterator<PGPSecretKey> keyIt = ring.getSecretKeys(); keyIt.hasNext(); ) {
                if (keyMatchesUserId(keyIt.next().getPublicKey(), userId)) {
                    return ring;
                }
            }
        }
        return null;
    }

    /**
     * Exact, case-insensitive match of {@code wanted} against any of a key's user IDs — matching
     * either the full user-ID string or the e-mail inside its angle brackets. Not a substring match.
     */
    private static boolean keyMatchesUserId(PGPPublicKey key, String wanted) {
        for (Iterator<String> it = key.getUserIDs(); it.hasNext(); ) {
            String candidate = it.next();
            if (candidate.equalsIgnoreCase(wanted)) {
                return true;
            }
            int lt = candidate.indexOf('<');
            int gt = candidate.indexOf('>', lt + 1);
            if (lt >= 0 && gt > lt && candidate.substring(lt + 1, gt).trim().equalsIgnoreCase(wanted)) {
                return true;
            }
        }
        return false;
    }

    private static PGPSecretKeyRing findSecretRingByFingerprint(PGPSecretKeyRingCollection secretKeys, byte[] fp) {
        for (Iterator<PGPSecretKeyRing> ringIt = secretKeys.getKeyRings(); ringIt.hasNext(); ) {
            PGPSecretKeyRing ring = ringIt.next();
            for (Iterator<PGPSecretKey> keyIt = ring.getSecretKeys(); keyIt.hasNext(); ) {
                if (Arrays.equals(keyIt.next().getPublicKey().getFingerprint(), fp)) {
                    return ring;
                }
            }
        }
        return null;
    }

    // Capability + validity resolution within a matched certificate

    /**
     * Choose a usable encryption key from a certificate: prefer the exact key the selector points at
     * (fingerprint / Key ID) when it can encrypt, otherwise the first encryption-capable (sub)key.
     * Revoked or expired keys are skipped; if an encryption-capable key exists but every such key is
     * revoked/expired, {@link CryptoError#KEY_UNUSABLE} is raised.
     *
     * @return a usable encryption key, or {@code null} if the certificate has no encryption-capable key.
     */
    private static PGPPublicKey pickEncryptionKey(PGPPublicKeyRing ring, KeySelector selector)
            throws CryptoException {
        byte[] fp = parseFingerprintOrNull(selector.getFingerprint());
        Long id = selector.getKeyId() == null ? null : parseKeyId(selector.getKeyId());
        boolean sawUnusable = false;
        for (Iterator<PGPPublicKey> it = ring.getPublicKeys(); it.hasNext(); ) {
            PGPPublicKey key = it.next();
            if (matches(key, fp, id) && key.isEncryptionKey()) {
                if (isUsable(key)) {
                    return key;
                }
                sawUnusable = true;
            }
        }
        for (Iterator<PGPPublicKey> it = ring.getPublicKeys(); it.hasNext(); ) {
            PGPPublicKey key = it.next();
            if (key.isEncryptionKey()) {
                if (isUsable(key)) {
                    return key;
                }
                sawUnusable = true;
            }
        }
        if (sawUnusable) {
            throw new CryptoException(CryptoError.KEY_UNUSABLE,
                    "The encryption key for " + selector.describe() + " is revoked or expired.");
        }
        return null;
    }

    /**
     * Choose a usable signing key from a certificate, with the same precedence and revocation/expiry
     * handling as {@link #pickEncryptionKey}.
     */
    private static PGPSecretKey pickSigningKey(PGPSecretKeyRing ring, KeySelector selector)
            throws CryptoException {
        byte[] fp = parseFingerprintOrNull(selector.getFingerprint());
        Long id = selector.getKeyId() == null ? null : parseKeyId(selector.getKeyId());
        boolean sawUnusable = false;
        for (Iterator<PGPSecretKey> it = ring.getSecretKeys(); it.hasNext(); ) {
            PGPSecretKey key = it.next();
            if (matches(key.getPublicKey(), fp, id) && key.isSigningKey()) {
                if (isUsable(key.getPublicKey())) {
                    return key;
                }
                sawUnusable = true;
            }
        }
        for (Iterator<PGPSecretKey> it = ring.getSecretKeys(); it.hasNext(); ) {
            PGPSecretKey key = it.next();
            if (key.isSigningKey()) {
                if (isUsable(key.getPublicKey())) {
                    return key;
                }
                sawUnusable = true;
            }
        }
        if (sawUnusable) {
            throw new CryptoException(CryptoError.KEY_UNUSABLE,
                    "The signing key for " + selector.describe() + " is revoked or expired.");
        }
        return null;
    }

    private static boolean matches(PGPPublicKey key, byte[] fp, Long id) {
        if (fp != null) {
            return Arrays.equals(key.getFingerprint(), fp);
        }
        return id != null && key.getKeyID() == id;
    }

    /** @return {@code true} if the key is neither revoked nor expired as of now. */
    private static boolean isUsable(PGPPublicKey key) {
        return !key.hasRevocation() && !isExpired(key, System.currentTimeMillis());
    }

    /** @return {@code true} if the key carries an expiry time that has passed at {@code atMillis}. */
    private static boolean isExpired(PGPPublicKey key, long atMillis) {
        long validSeconds = key.getValidSeconds();
        if (validSeconds <= 0L) {
            return false;
        }
        long expiresAt = key.getCreationTime().getTime() + validSeconds * 1000L;
        return atMillis > expiresAt;
    }

    /**
     * Reject a signer's key that is untrusted: revoked, or expired at the time the signature was made.
     * Called on verify / decrypt-then-verify when {@code requireValidSignerKey} is set.
     */
    public static void validateSignerKey(PGPPublicKey signerKey, java.util.Date signatureTime)
            throws CryptoException {
        if (signerKey.hasRevocation()) {
            throw new CryptoException(CryptoError.SIGNER_KEY_UNTRUSTED,
                    "Signature rejected: the signer's key (key ID " + hex(signerKey.getKeyID()) + ") is revoked.");
        }
        long at = signatureTime != null ? signatureTime.getTime() : System.currentTimeMillis();
        if (isExpired(signerKey, at)) {
            throw new CryptoException(CryptoError.SIGNER_KEY_UNTRUSTED,
                    "Signature rejected: the signer's key (key ID " + hex(signerKey.getKeyID())
                    + ") had expired when the signature was made.");
        }
    }

    /**
     * Parse a 64-bit OpenPGP Key ID. The input is treated strictly as hexadecimal (a
     * {@code 0x} prefix, spaces and colons are stripped) and decoded as an unsigned long, matching
     * the 16-character Key ID form used by MuleSoft-style configurations.
     */
    private static long parseKeyId(String keyId) throws CryptoException {
        String clean = stripHex(keyId);
        try {
            return Long.parseUnsignedLong(clean, 16);
        } catch (NumberFormatException e) {
            throw new CryptoException(CryptoError.INVALID_CONFIGURATION,
                    "Invalid Key ID (expected a 16-character hex value such as 0x7B9E1A2C3D4E5F6A): " + keyId, e);
        }
    }

    /**
     * Parse a key fingerprint (hex; a {@code 0x} prefix, spaces and colons are tolerated) into
     * bytes using {@link Hex#decode}, or return {@code null} when the input is blank.
     */
    private static byte[] parseFingerprintOrNull(String fingerprint) throws CryptoException {
        if (fingerprint == null || fingerprint.trim().isEmpty()) {
            return null;
        }
        String clean = stripHex(fingerprint);
        if (clean.isEmpty() || clean.length() % 2 != 0) {
            throw new CryptoException(CryptoError.INVALID_CONFIGURATION, "Invalid key fingerprint: " + fingerprint);
        }
        try {
            return Hex.decode(clean);
        } catch (RuntimeException e) {
            throw new CryptoException(CryptoError.INVALID_CONFIGURATION,
                    "Invalid key fingerprint (non-hex): " + fingerprint, e);
        }
    }

    private static String hex(long keyId) {
        return "0x" + String.format("%016X", keyId);
    }

    /**
     * Normalise a user-supplied hex value (Key ID or fingerprint) by trimming and stripping a
     * {@code 0x} prefix, whitespace and colon separators.
     */
    private static String stripHex(String value) {
        return value.trim().replaceAll("(?i)0x|\\s+|:", "");
    }

    private static String describeSource(String source) {
        if (source == null) {
            return "<none>";
        }
        String trimmed = source.trim();
        if (trimmed.contains(PGPCryptoConstants.ARMOR_HEADER_PREFIX)) {
            return "inline key content";
        }
        return trimmed;
    }
}
