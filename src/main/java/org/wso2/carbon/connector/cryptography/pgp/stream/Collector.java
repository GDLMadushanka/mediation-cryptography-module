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

import java.io.OutputStream;

/**
 * A sink Bouncy Castle's generators write into and a stream reads out of.
 *
 * <p>The awkwardness is BC's, not ours. Its generators are push: you are handed an
 * {@code OutputStream} and write into it. A sequence is pull: the sink calls {@code read()}. The
 * usual bridge is a second thread and a piped stream; this is the alternative — the generators write
 * here and each {@code read()} feeds them just enough input to produce something to serve. One
 * thread, no handoff, and backpressure for free, because nothing is read from upstream until the
 * consumer asks.
 *
 * <p>Grows to whatever one round of generator output needs and then stays that size, so a steady
 * transfer allocates nothing per chunk. Compacts to the front when drained rather than copying on
 * every read.
 */
final class Collector extends OutputStream {

    /** Partial-length packet buffer. Sized with the chunk size, not against it. */
    static final int PACKET_BUFFER = 64 * 1024;

    private byte[] buffer = new byte[PACKET_BUFFER];
    private int writePosition;
    private int readPosition;

    @Override
    public void write(int b) {
        ensure(1);
        buffer[writePosition++] = (byte) b;
    }

    @Override
    public void write(byte[] b, int off, int len) {
        ensure(len);
        System.arraycopy(b, off, buffer, writePosition, len);
        writePosition += len;
    }

    int available() {
        return writePosition - readPosition;
    }

    int drain(byte[] destination, int off, int len) {
        int n = Math.min(len, available());
        System.arraycopy(buffer, readPosition, destination, off, n);
        readPosition += n;
        if (readPosition == writePosition) {
            readPosition = 0;
            writePosition = 0;
        }
        return n;
    }

    private void ensure(int extra) {
        if (writePosition + extra <= buffer.length) {
            return;
        }
        int held = available();
        if (readPosition > 0 && held + extra <= buffer.length) {
            System.arraycopy(buffer, readPosition, buffer, 0, held);
            readPosition = 0;
            writePosition = held;
            return;
        }
        int size = Math.max(buffer.length * 2, held + extra);
        byte[] grown = new byte[size];
        System.arraycopy(buffer, readPosition, grown, 0, held);
        buffer = grown;
        readPosition = 0;
        writePosition = held;
    }
}
