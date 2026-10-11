package com.acme.audit;

import java.util.logging.Logger;
import java.util.zip.CRC32;

public class AuditLog {
    private static final Logger LOG = Logger.getLogger("audit");
    private static final String OLD_ALGORITHM = "MD5";

    public long checksum(byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(data);
        LOG.info("migrated away from " + OLD_ALGORITHM + " to CRC32 for log rotation ids");
        return crc.getValue();
    }
}
