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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * The guarantee strict mode exists to provide: a verdict that only arrives at the end of a stream
 * still decides whether anything downstream sees the stream at all.
 *
 * <p>These tests are deliberately free of OpenPGP. What makes a verifying stage safe is not the
 * cryptography — that is {@link PgpStreamRoundTripTest}'s subject — but the ordering: upstream must
 * reach its end, and be given its chance to throw, before one byte is served. Testing that with a
 * stream that simply throws at EOF says exactly that and nothing else.
 */
public class BarrierStreamTest {

    private Path scratch;

    @Before
    public void makeScratch() throws IOException {
        scratch = Files.createTempDirectory("barrier-test");
    }

    @After
    public void removeScratch() throws IOException {
        if (scratch == null || !Files.exists(scratch)) {
            return;
        }
        try (java.util.stream.Stream<Path> walk = Files.walk(scratch)) {
            for (Path path : walk.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    /** An upstream that fails at the end, the way a signature check does. */
    private static InputStream failingAtEof(byte[] content, String complaint) {
        return new FilterInputStream(new ByteArrayInputStream(content)) {
            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                int n = super.read(b, off, len);
                if (n == -1) {
                    throw new IOException(complaint);
                }
                return n;
            }
        };
    }

    private BarrierStream barrier(InputStream upstream, Long cap, List<Long> progress,
                                  AtomicBoolean cancelled) {
        return new BarrierStream(upstream, "test", () -> scratch, cap, null,
                progress::add, cancelled::get);
    }

    private BarrierStream barrier(InputStream upstream) {
        return barrier(upstream, null, new ArrayList<>(), new AtomicBoolean(false));
    }

    private static byte[] drain(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int n;
        while ((n = in.read(chunk)) != -1) {
            out.write(chunk, 0, n);
        }
        return out.toByteArray();
    }

    @Test
    public void aGoodStreamIsServedWholeOnceItHasBeenDrained() throws Exception {
        byte[] content = "the quick brown fox\n".repeat(5000).getBytes(StandardCharsets.UTF_8);
        try (BarrierStream stream = barrier(new ByteArrayInputStream(content))) {
            assertArrayEquals(content, drain(stream));
        }
    }

    @Test
    public void anEmptyStreamIsServedAsEmpty() throws Exception {
        try (BarrierStream stream = barrier(new ByteArrayInputStream(new byte[0]))) {
            assertEquals(0, drain(stream).length);
        }
    }

    @Test
    public void aFailureAtTheEndOfUpstreamReachesTheVeryFirstRead() throws Exception {
        // The whole point. The upstream serves 100 KiB happily and only objects at EOF; without the
        // barrier every one of those bytes would already be at the destination.
        byte[] content = new byte[100 * 1024];
        InputStream upstream = failingAtEof(content, "signature did NOT match");
        try (BarrierStream stream = barrier(upstream)) {
            stream.read(new byte[1], 0, 1);
            fail("the first read must carry upstream's verdict, not a byte of its data");
        } catch (IOException expected) {
            assertEquals("signature did NOT match", expected.getMessage());
        }
    }

    @Test
    public void notAByteIsServedWhenTheVerdictIsBad() throws Exception {
        byte[] content = "secret payload\n".repeat(1000).getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream served = new ByteArrayOutputStream();
        try (BarrierStream stream = barrier(failingAtEof(content, "forged"))) {
            byte[] chunk = new byte[256];
            int n;
            while ((n = stream.read(chunk)) != -1) {
                served.write(chunk, 0, n);
            }
            fail("a forged message must not be served");
        } catch (IOException expected) {
            assertEquals("forged", expected.getMessage());
        }
        assertEquals("nothing at all may reach the consumer", 0, served.size());
    }

    @Test
    public void aConfiguredCapStopsAnOversizedMessage() throws Exception {
        byte[] content = new byte[64 * 1024];
        try (BarrierStream stream = barrier(new ByteArrayInputStream(content), 1024L,
                new ArrayList<>(), new AtomicBoolean(false))) {
            drain(stream);
            fail("a message past maxPlaintextSize must be refused");
        } catch (IOException expected) {
            assertTrue("the message should name the limit that was hit, got: "
                            + expected.getMessage(),
                    expected.getMessage().contains("maxPlaintextSize"));
            assertTrue("the message should explain why there is a limit at all, got: "
                            + expected.getMessage(),
                    expected.getMessage().contains("decompress"));
        }
    }

    @Test
    public void cancellationStopsTheDrainRatherThanRunningToTheEnd() throws Exception {
        AtomicBoolean cancelled = new AtomicBoolean(true);
        try (BarrierStream stream = barrier(new ByteArrayInputStream(new byte[64 * 1024]), null,
                new ArrayList<>(), cancelled)) {
            drain(stream);
            fail("a cancelled run must not finish the drain");
        } catch (IOException expected) {
            assertTrue("expected a cancellation message, got: " + expected.getMessage(),
                    expected.getMessage().contains("cancelled"));
        }
    }

    @Test
    public void progressIsReportedWhileTheSinkHasNothingToDo() throws Exception {
        // Without this a strict-mode transfer looks stalled for however long the drain takes, which
        // is the complaint that produced WORKING_MILLIS in the first place.
        List<Long> progress = new ArrayList<>();
        byte[] content = new byte[256 * 1024];
        try (BarrierStream stream = barrier(new ByteArrayInputStream(content), null, progress,
                new AtomicBoolean(false))) {
            drain(stream);
        }
        assertFalse("the drain must report progress", progress.isEmpty());
        assertEquals("the last report must be the whole message",
                Long.valueOf(content.length), progress.get(progress.size() - 1));
    }

    @Test
    public void theHeldCopyIsRemovedWhenTheStreamIsClosed() throws Exception {
        byte[] content = new byte[32 * 1024];
        BarrierStream stream = barrier(new ByteArrayInputStream(content));
        drain(stream);
        try (java.util.stream.Stream<Path> files = Files.list(scratch)) {
            assertTrue("the drain should have written a file", files.findAny().isPresent());
        }
        stream.close();
        try (java.util.stream.Stream<Path> files = Files.list(scratch)) {
            assertFalse("a transfer must not sit on a second copy of its own plaintext",
                    files.findAny().isPresent());
        }
    }
}
