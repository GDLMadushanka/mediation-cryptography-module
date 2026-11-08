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

import org.apache.axiom.om.OMElement;
import org.apache.synapse.MessageContext;
import org.apache.synapse.stream.StreamException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.wso2.carbon.connector.cryptography.exception.CryptoException;
import org.wso2.carbon.connector.cryptography.pgp.connection.PgpKeyStore;
import org.wso2.carbon.connector.cryptography.pgp.connection.PgpKeyStoreHandler;
import org.wso2.carbon.connector.cryptography.pgp.constant.PGPParameterKey;
import org.wso2.carbon.connector.cryptography.pgp.util.PGPKeyUtils;
import org.wso2.integration.connector.core.util.ConnectorUtils;

import org.apache.synapse.stream.StreamContext;

import java.io.InputStream;
import java.util.Iterator;
import java.util.Locale;

/**
 * Parameter reading and connection lookup, shared by every PGP stream operator.
 *
 * <p>Six operators need the same four things: a template parameter, a boolean one, a byte size, and
 * the key store the stage was given. Before this class each copy was private to one operator, which
 * is how two of them came to disagree about whether an empty string means "unset".
 *
 * <p>All static. There is deliberately no base class: the operators implement different stream roles
 * and already extend {@code AbstractConnector}, so inheritance would buy nothing and spend the one
 * superclass slot.
 */
final class PgpStreamSupport {

    /**
     * The synapse property the connection's own template leaves the connection name in.
     *
     * <p><b>Not a template parameter.</b> The sequence does not mediate an operator's template — it
     * takes the stream role out of the {@code <class>} mediator and drives it directly — so the
     * connection arrives as {@code configKey} on the stage element instead. The framework mediates
     * that local entry, which <i>is</i> an ordinary template, so its own
     * {@code <property name="name"/>} does run and leaves the name here.
     */
    private static final String CONNECTION_NAME = "name";

    private PgpStreamSupport() {
    }

    /** A bound template parameter, or {@code null} when absent or blank. */
    static String param(MessageContext msg, String name) {
        Object value = ConnectorUtils.lookupTemplateParamater(msg, name);
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }

    static String param(MessageContext msg, String name, String fallback) {
        String value = param(msg, name);
        return value == null ? fallback : value;
    }

    static boolean boolParam(MessageContext msg, String name, boolean fallback) {
        String value = param(msg, name);
        return value == null ? fallback : Boolean.parseBoolean(value);
    }

    /**
     * A byte size written the way a deployer writes one: {@code 512M}, {@code 512MB}, {@code 512MiB}.
     *
     * <p>All three mean the same number of bytes. Arguing about MB versus MiB in a configuration file
     * wastes everyone's afternoon and the difference has never mattered to anything this reads.
     *
     * @return the size in bytes, or {@code null} when the parameter is absent
     * @throws IllegalArgumentException if present but unparseable
     */
    static Long sizeParam(MessageContext msg, String name) {
        String value = param(msg, name);
        if (value == null) {
            return null;
        }
        String text = value.toUpperCase(Locale.ROOT).replace("IB", "B");
        long multiplier = 1L;
        if (text.endsWith("KB") || text.endsWith("K")) {
            multiplier = 1024L;
        } else if (text.endsWith("MB") || text.endsWith("M")) {
            multiplier = 1024L * 1024L;
        } else if (text.endsWith("GB") || text.endsWith("G")) {
            multiplier = 1024L * 1024L * 1024L;
        } else if (text.endsWith("TB") || text.endsWith("T")) {
            multiplier = 1024L * 1024L * 1024L * 1024L;
        }
        String digits = text.replaceAll("[^0-9]", "");
        if (digits.isEmpty()) {
            throw new IllegalArgumentException("[" + name + "] of '" + value + "' is not a size."
                    + " Write it as a number with an optional unit, for example 512M, 512MB or"
                    + " 512MiB — all three mean the same thing.");
        }
        return Long.parseLong(digits) * multiplier;
    }

    /** The connection name on the stage, falling back to a bound parameter. */
    static String connectionName(MessageContext msg, String fallbackParameter) {
        Object configured = msg.getProperty(CONNECTION_NAME);
        if (configured != null && !configured.toString().trim().isEmpty()) {
            return configured.toString().trim();
        }
        return param(msg, fallbackParameter);
    }

    /**
     * Resolves the key store a stage was given, refusing clearly when it is the wrong kind.
     *
     * <p>The wrong-kind check earns its place: a public key store configured where a private one
     * belongs fails deep inside Bouncy Castle with a message about key IDs that points nowhere near
     * the configuration mistake that caused it.
     *
     * @param operator       the operator name, for the message
     * @param connectionName what the stage named, possibly {@code null}
     * @param wantPrivate    whether this operator needs our secret keys or someone else's public ones
     * @param purpose        a short phrase completing "…needs <purpose>"
     */
    static PgpKeyStore store(String operator, String connectionName, boolean wantPrivate,
                             String purpose) throws StreamException {
        if (connectionName == null) {
            throw new StreamException(operator + " has no key store connection. Put the "
                    + (wantPrivate ? "PGP private key" : "PGP public key")
                    + " connection on the stage as configKey=\"...\".", false);
        }
        PgpKeyStore store = PgpKeyStoreHandler.get(connectionName);
        if (store == null) {
            throw new StreamException(operator + ": PGP key store connection '" + connectionName
                    + "' is not deployed or failed to initialise", false);
        }
        if (wantPrivate && !store.isPrivate()) {
            throw new StreamException(operator + ": connection '" + connectionName + "' is a public"
                    + " key store; " + purpose, false);
        }
        if (!wantPrivate && store.isPrivate()) {
            throw new StreamException(operator + ": connection '" + connectionName + "' is a private"
                    + " key store; " + purpose, false);
        }
        return store;
    }

    /**
     * A second key store, named by parameter rather than by the stage's {@code configKey}.
     *
     * <p>Three operators need two connections — one to decrypt or encrypt with, another to sign or
     * verify with — and a stage element carries one {@code configKey}. The framework mediates that
     * one entry while binding the stage's parameters, which is what registers it; the second is named
     * by a parameter and nothing mediates it.
     *
     * <p>In an ordinary sequence the connector solves this by putting two
     * {@code <cryptography.invokeConnection>} elements in the operation's template. A sequence never
     * mediates an operator's template body — it lifts the stream role out of the {@code <class>} and
     * drives it directly — so that route does not exist here.
     *
     * <p>So: use the registered store when something already registered it, and otherwise read the
     * connection's own local entry and build the store from it. The fallback runs the same few lines
     * {@code PgpKeyStoreInit} would, against the same configuration, and registers the result so the
     * next run of the same sequence takes the fast path.
     *
     * @param wantPrivate whether this is our own secret key store or someone else's public one
     * @param parameter   the parameter that named it, for the message when it is missing
     * @param purpose     a short phrase completing "…because <purpose>"
     */
    static PgpKeyStore secondaryKeyStore(MessageContext msg, String operator, String connectionName,
                                         boolean wantPrivate, String parameter, String purpose)
            throws StreamException {
        if (connectionName == null) {
            throw new StreamException(operator + " has no <" + parameter + ">. Name the PGP "
                    + (wantPrivate ? "private" : "public") + " key connection to use, because "
                    + purpose, false);
        }
        PgpKeyStore registered = PgpKeyStoreHandler.get(connectionName);
        if (registered != null) {
            if (registered.isPrivate() != wantPrivate) {
                throw new StreamException(operator + ": <" + parameter + "> names '" + connectionName
                        + "', which is a " + (registered.isPrivate() ? "private" : "public")
                        + " key store, but " + purpose, false);
            }
            return registered;
        }
        return buildFromLocalEntry(msg, operator, connectionName, wantPrivate, parameter);
    }

    private static PgpKeyStore buildFromLocalEntry(MessageContext msg, String operator, String name,
                                                   boolean wantPrivate, String parameter)
            throws StreamException {
        Object entry = msg.getConfiguration() == null ? null : msg.getConfiguration().getEntry(name);
        OMElement init = entry instanceof OMElement ? findInit((OMElement) entry) : null;
        if (init == null) {
            throw new StreamException(operator + ": PGP key store connection '" + name + "' is not"
                    + " deployed, or is not a cryptography connection. <" + parameter + "> must name"
                    + " a deployed PGP " + (wantPrivate ? "Private" : "Public") + " Key connection.",
                    false);
        }
        String keyIdentifier = childText(init, PGPParameterKey.KEY_IDENTIFIER);
        try {
            if (wantPrivate) {
                String path = required(init, PGPParameterKey.PRIVATE_KEY_PATH, operator, name,
                        parameter, "private");
                PgpKeyStore store = PgpKeyStore.privateStore(name, keyIdentifier,
                        PGPKeyUtils.loadSecretKeyRingCollection(msg, path),
                        childText(init, PGPParameterKey.PASSPHRASE));
                PgpKeyStoreHandler.add(store);
                return store;
            }
            String path = required(init, PGPParameterKey.PUBLIC_KEY_PATH, operator, name, parameter,
                    "public");
            PGPPublicKeyRingCollection keys = PGPKeyUtils.loadPublicKeyRingCollection(msg, path);
            PgpKeyStore store = PgpKeyStore.publicStore(name, keyIdentifier, keys);
            PgpKeyStoreHandler.add(store);
            return store;
        } catch (CryptoException e) {
            throw new StreamException(operator + " could not load the key store '" + name + "' named"
                    + " by <" + parameter + ">: " + e.getMessage(), e, false);
        }
    }

    private static String required(OMElement init, String element, String operator, String name,
                                   String parameter, String kind) throws StreamException {
        String value = childText(init, element);
        if (value == null) {
            throw new StreamException(operator + ": connection '" + name + "' declares no " + element
                    + ", so it is not a PGP " + kind + " key connection. Check what <" + parameter
                    + "> points at.", false);
        }
        return value;
    }

    /** The {@code <cryptography.init>} element, whether the entry is it or merely wraps it. */
    private static OMElement findInit(OMElement entry) {
        if (entry.getLocalName() != null && entry.getLocalName().endsWith("init")) {
            return entry;
        }
        for (Iterator<?> it = entry.getChildElements(); it.hasNext(); ) {
            OMElement found = findInit((OMElement) it.next());
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    private static String childText(OMElement parent, String localName) {
        for (Iterator<?> it = parent.getChildElements(); it.hasNext(); ) {
            OMElement child = (OMElement) it.next();
            if (localName.equals(child.getLocalName())) {
                String text = child.getText();
                return text == null || text.trim().isEmpty() ? null : text.trim();
            }
        }
        return null;
    }

    /** How much of the message a verifying stage holds back. */
    static final String MODE = "mode";

    /** Hold everything until the signature has been checked. The default. */
    static final String MODE_STRICT = "strict";

    /** Serve as it goes, and let a failed run's {@code abort()} undo whatever was done with it. */
    static final String MODE_STREAMING = "streaming";

    /** The cap on plaintext written while holding a message. */
    static final String MAX_PLAINTEXT_SIZE = "maxPlaintextSize";

    /**
     * Wraps a verifying stream in a {@link BarrierStream} unless the deployer opted out.
     *
     * <p><b>Strict is the default, and that is a deliberate inversion of the usual instinct.</b>
     * Someone who reached for a verifying operator asked for the guarantee that a forged message
     * changes nothing. They should not also have to know which sinks publish atomically, nor that
     * {@code ResourceScope.abort()} cannot un-send an HTTP request a {@code forEach} already made,
     * in order to actually get it. A control that is only correct if you understand the rest of the
     * architecture is not a control.
     *
     * <p>{@code mode=streaming} is the opt-out, and it is the right choice for a sequence that only
     * moves bytes into a sink that publishes at commit — which is most MFT transfers. It halves the
     * wall clock, because the drain and the upload overlap again.
     */
    static InputStream applyMode(InputStream verifying, String operator, MessageContext msg,
                                 StreamContext ctx) throws StreamException {
        String mode = param(msg, MODE, MODE_STRICT);
        if (MODE_STREAMING.equalsIgnoreCase(mode)) {
            return verifying;
        }
        if (!MODE_STRICT.equalsIgnoreCase(mode)) {
            throw new StreamException(operator + ": <mode> of '" + mode + "' is not a mode. It is"
                    + " either '" + MODE_STRICT + "' (the default — hold the message until its"
                    + " signature has been checked) or '" + MODE_STREAMING + "' (serve as it goes,"
                    + " safe only where a failed run undoes everything downstream).", false);
        }
        Long cap;
        try {
            cap = sizeParam(msg, MAX_PLAINTEXT_SIZE);
        } catch (IllegalArgumentException e) {
            throw new StreamException(operator + ": " + e.getMessage(), e, false);
        }
        String stage = ctx.stageName();
        return new BarrierStream(verifying, operator, ctx::scratch, cap, ctx.job().expectedSize(),
                bytes -> ctx.job().progress(stage, bytes, 0L), ctx.job()::isCancelled);
    }
}
