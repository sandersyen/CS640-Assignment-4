package org.openflow.protocol.statistics;

import java.nio.ByteBuffer;

/**
 * Represents an ofp_aggregate_stats_reply structure
 * @author David Erickson (daviderickson@cs.stanford.edu)
 */
public class OFAggregateStatisticsReply implements OFStatistics {
    protected static int MINIMUM_LENGTH = 24;

    protected long packetCount;
    protected long byteCount;
    protected int flowCount;

    /**
     * @return the packetCount
     */
    public long getPacketCount() {
        return packetCount;
    }

    /**
     * @param packetCount the packetCount to set
     */
    public OFAggregateStatisticsReply setPacketCount(long packetCount) {
        this.packetCount = packetCount;
        return this;
    }

    /**
     * @return the byteCount
     */
    public long getByteCount() {
        return byteCount;
    }

    /**
     * @param byteCount the byteCount to set
     */
    public OFAggregateStatisticsReply setByteCount(long byteCount) {
        this.byteCount = byteCount;
        return this;
    }

    /**
     * @return the flowCount
     */
    public int getFlowCount() {
        return flowCount;
    }

    /**
     * @param flowCount the flowCount to set
     */
    public OFAggregateStatisticsReply setFlowCount(int flowCount) {
        this.flowCount = flowCount;
        return this;
    }

    @Override
    public int getLength() {
        return MINIMUM_LENGTH;
    }

    @Override
    public void readFrom(ByteBuffer data) {
        this.packetCount = data.getLong();
        this.byteCount = data.getLong();
        this.flowCount = data.getInt();
        data.getInt(); // pad
    }

    @Override
    public void writeTo(ByteBuffer data) {
        data.putLong(this.packetCount);
        data.putLong(this.byteCount);
        data.putInt(this.flowCount);
        data.putInt(0); // pad
    }

    @Override
    public int hashCode() {
        final int prime = 397;
        int result = 1;
        result = prime * result + (int) (byteCount ^ (byteCount >>> 32));
        result = prime * result + flowCount;
        result = prime * result + (int) (packetCount ^ (packetCount >>> 32));
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof OFAggregateStatisticsReply)) {
            return false;
        }
        OFAggregateStatisticsReply other = (OFAggregateStatisticsReply) obj;
        if (byteCount != other.byteCount) {
            return false;
        }
        if (flowCount != other.flowCount) {
            return false;
        }
        if (packetCount != other.packetCount) {
            return false;
        }
        return true;
    }

    @Override
    public int computeLength() {
        return getLength();
    }
}
