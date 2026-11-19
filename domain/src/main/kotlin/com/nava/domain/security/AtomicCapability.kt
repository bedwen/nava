package com.nava.domain.security

/**
 * The five orthogonal, non-hierarchical capability switches governing every app,
 * notification source, system domain, and SAF directory in Nava.
 */
enum class AtomicCapability {
    /** Read and summarize notifications from a permitted source. */
    NOTIFICATION_READ,

    /** Query calendar events, alarms, or permitted SAF directory files. */
    DATA_READ,

    /** Create a new alarm, calendar event, note, or message draft. */
    CREATE_DRAFT,

    /** Modify or delete existing records or initiate sensitive outbound actions. */
    MODIFY_DELETE_SEND,

    /** Launch an application via allowlisted intent templates. */
    APP_LAUNCH
}
