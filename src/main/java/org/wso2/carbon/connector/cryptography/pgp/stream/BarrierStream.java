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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.function.BooleanSupplier;
import java.util.function.LongConsumer;
import java.util.function.Supplier;

/**
 * Serves nothing until its upstream has been read to the end.
 *
 * <p>The piece that turns "this message failed verification" into "nothing downstream ever saw it".
 * A verifying stream can only reach its verdict at the last byte, so by the time it knows, the bytes
 * have already gone. This drains the whole of that stream into a scratch file first — which is where
 * the verdict lands, as an exception thrown during the drain — and only then begins serving. On a
 * bad signature, the first {@code read()} a downstream stage ever makes is the one that throws.
 *
 * <h2>Why this is not {@code materialises()}</h2>
 * Framework materialisation writes an artifact <i>and</i> serves the same bytes downstream as it
 * goes, so it would not hold anything back. Worse, on a resumed run the framework serves the
 * artifact's prefix directly and the operator re-derives only the tail — so a verifying stage would
 * hash the tail alone and check a whole-message signature against it. Materialisation and signature
 * verification cannot be combined; this is the alternative, and it lives in the operator because
 * {@code scratch()} is deliberately ungated by capability flags.
 *
 * <h2>The cost, stated plainly</h2>
 * Nothing overlaps. The sink sits idle while the drain runs and the drain is idle while the sink
 * writes, so wall clock is the sum rather than the larger of the two — roughly double for a transfer
 * bounded by one network. That is the price of the guarantee, and it is why the streaming mode
 * remains available for a sequence whose every stage can be rolled back by {@code abort()}.
 *
 * <h2>Untrusted data lands on our disk before it is trusted</h2>
 * Strict mode exists precisely because the sender is not trusted yet, and the drain writes what the
 * sender sent — after decompression. A few megabytes of OpenPGP can carry a great many gigabytes of
 * deflate, so the drain is capped: by {@code maxPlaintextSize} when the deployer sets one, and in
 * every case by the free space actually on the volume, re-checked as it goes because this is not the
 * only thing using that disk.
 */
final class BarrierStream extends InputStream {

    private static final int COPY_BUFFER = 64 * 1024;

    /** Re-stat the volume this often; a long compare per chunk is free, a syscall is not. */
    private static final long RECHECK_EVERY = 1024L * 1024L * 1024L;

    /** Never plan to use the last of the disk, whatever the arithmetic says. */
    private static final long MIN_HEADROOM = 64L * 1024L * 1024L;

    /** …or this share of it, whichever is larger. */
    private static final int HEADROOM_SHARE = 20;

    private final InputStream upstream;
    private final String operator;
    private final Supplier<Path> scratch;
    private final Long configuredCap;
    private final Long expectedSourceSize;
    private final LongConsumer progress;
    private final BooleanSupplier cancelled;

    private Path file;
    private InputStream served;
    private boolean drained;

    /**
     * @param scratch            this stage's scratch directory, resolved lazily — obtaining it
     *                           creates a directory, which {@code wrap()} may not do
     * @param configuredCap      {@code maxPlaintextSize}, or {@code null} for free space alone
     * @param expectedSourceSize the source's size if the framework knows it, for the pre-flight
     */
    BarrierStream(InputStream upstream, String operator, Supplier<Path> scratch, Long configuredCap,
                  Long expectedSourceSize, LongConsumer progress, BooleanSupplier cancelled) {
        this.upstream = upstream;
        this.operator = operator;
        this.scratch = scratch;
        this.configuredCap = configuredCap;
        this.expectedSourceSize = expectedSourceSize;
        this.progress = progress;
        this.cancelled = cancelled;
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
        if (!drained) {
            drain();
        }
        return served.read(b, off, len);
    }

    /**
     * Reads the whole of upstream into scratch, then opens it for serving.
     *
     * <p>Anything upstream throws at its own end — a bad signature, a failed integrity check — comes
     * out of here, before a single byte has been served. That is the entire point of the class.
     */
    private void drain() throws IOException {
        Path directory = scratch.get();
        long usable = usableSpace(directory);
        preflight(usable);
        long budget = budget(usable);

        file = directory.resolve("barrier.plaintext");
        long written = 0L;
        long nextRecheck = RECHECK_EVERY;
        byte[] buffer = new byte[COPY_BUFFER];
        try (OutputStream out = new BufferedOutputStream(Files.newOutputStream(file,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE), COPY_BUFFER)) {
            int n;
            while ((n = upstream.read(buffer)) != -1) {
                if (cancelled.getAsBoolean()) {
                    // Non-retryable: someone asked this transfer to stop, and re-queueing it would
                    // start the drain over rather than honour that.
                    String stopped = operator + " was cancelled after " + mib(written)
                            + " while holding the message for verification";
                    throw new IOException(stopped, new StreamException(stopped, false));
                }
                written += n;
                if (written > budget) {
                    // Non-retryable when the deployer set the limit: the same message against the
                    // same configuration gives the same answer, four more times.
                    String refusal = tooBig(written, budget, usable);
                    throw configuredCap != null && configuredCap <= budget
                            ? new IOException(refusal, new StreamException(refusal, false))
                            : new IOException(refusal);
                }
                out.write(buffer, 0, n);
                progress.accept(written);
                if (written >= nextRecheck) {
                    nextRecheck = written + RECHECK_EVERY;
                    long nowUsable = usableSpace(directory);
                    if (nowUsable < MIN_HEADROOM) {
                        throw new IOException(operator + " stopped after " + mib(written)
                                + ": the scratch volume at '" + directory + "' is down to "
                                + mib(nowUsable) + " free. Something else is filling it, or this"
                                + " message is larger than the volume can hold.");
                    }
                }
            }
        }
        // Only now, with upstream at its end and every check it carries already passed.
        served = new BufferedInputStream(Files.newInputStream(file), COPY_BUFFER);
        drained = true;
    }

    /**
     * Refuses before reading a byte when the volume plainly cannot hold the message.
     *
     * <p>The source size is the <i>ciphertext</i>, so it is a lower bound on the plaintext and never
     * an estimate of it — a compressed message decompresses to more, sometimes to far more. Failing
     * on the lower bound still catches the honest mistakes, and does it in a second rather than four
     * hours in.
     */
    private void preflight(long usable) throws IOException {
        if (expectedSourceSize == null || expectedSourceSize <= 0) {
            return;
        }
        long needed = expectedSourceSize + headroom(usable);
        if (usable < needed) {
            throw new IOException(operator + " needs to hold the whole message before it can release"
                    + " it, but the scratch volume has only " + mib(usable) + " free and the message"
                    + " is at least " + mib(expectedSourceSize) + " — more once decompressed. Give"
                    + " the scratch volume more room, point mft.scratch.root at a larger one, or set"
                    + " mode=streaming if every stage below this one can be rolled back by a failed"
                    + " run.");
        }
    }

    private long budget(long usable) {
        long fromDisk = Math.max(0L, usable - headroom(usable));
        return configuredCap == null ? fromDisk : Math.min(configuredCap, fromDisk);
    }

    private static long headroom(long usable) {
        return Math.max(MIN_HEADROOM, usable / HEADROOM_SHARE);
    }

    private String tooBig(long written, long budget, long usable) {
        String limit = configuredCap != null && configuredCap <= budget
                ? "the configured maxPlaintextSize of " + mib(configuredCap)
                : "what the scratch volume can spare (" + mib(usable) + " free, keeping "
                        + mib(headroom(usable)) + " back)";
        return operator + " stopped after writing " + mib(written) + " of plaintext, which is past "
                + limit + ". A small OpenPGP message can decompress to an enormous one, and this"
                + " stage holds the whole of it before releasing any — so the limit is a guard"
                + " against a sender, trusted or not, filling this volume. Raise maxPlaintextSize if"
                + " the message really is this large.";
    }

    private static long usableSpace(Path directory) throws IOException {
        return Files.getFileStore(directory).getUsableSpace();
    }

    private static String mib(long bytes) {
        if (bytes >= 1024L * 1024L * 1024L) {
            return String.format("%.2f GiB", bytes / (1024.0 * 1024.0 * 1024.0));
        }
        return String.format("%.0f MiB", Math.ceil(bytes / (1024.0 * 1024.0)));
    }

    @Override
    public void close() throws IOException {
        try {
            if (served != null) {
                served.close();
            }
        } finally {
            try {
                // The framework removes the scratch directory when the run ends, but a long transfer
                // should not sit on a second copy of its own plaintext until then.
                if (file != null) {
                    Files.deleteIfExists(file);
                }
            } finally {
                upstream.close();
            }
        }
    }
}
