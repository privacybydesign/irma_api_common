package org.irmacard.api.common;

public class ProtocolVersion {
    private int major;
    private int minor;

    public ProtocolVersion(int major, int minor) {
        this.major = major;
        this.minor = minor;
    }

    public ProtocolVersion(String versionString) {
        String[] parts = versionString.split("\\.");
        if (parts.length != 2) {
            throw new IllegalArgumentException("invalid version string:" + versionString + "..." + parts.length);
        }
        this.major = Integer.parseInt(parts[0]);
        this.minor = Integer.parseInt(parts[1]);
    }

    public static ProtocolVersion valueOf(String v) {
        return new ProtocolVersion(v);
    }

    public boolean below(ProtocolVersion other) {
        return this.major < other.major || this.major == other.major && this.minor < other.minor;
    }

    public boolean above(ProtocolVersion other) {
        return this.major > other.major || this.major == other.major && this.minor > other.minor;
    }

    public boolean equal(ProtocolVersion other) {
        return this.major == other.major && this.minor == other.minor;
    }

    public String toString() {
        return major + "." + minor;
    }
}
