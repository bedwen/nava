package com.nava.app.ui.audit

import org.junit.Assert.assertEquals
import org.junit.Test

class AuditLogDecisionStyleTest {

    @Test
    fun classifyAuditDecision_verifiedDecisionsMapToVerified() {
        assertEquals(AuditDecisionSeverity.VERIFIED, classifyAuditDecision("SUCCESS"))
        assertEquals(AuditDecisionSeverity.VERIFIED, classifyAuditDecision("ALLOWED"))
    }

    @Test
    fun classifyAuditDecision_warningDecisionsMapToWarning() {
        assertEquals(
            AuditDecisionSeverity.WARNING,
            classifyAuditDecision("CONFIRMATION_REQUIRED")
        )
        assertEquals(
            AuditDecisionSeverity.WARNING,
            classifyAuditDecision("ESCALATED_BIOMETRIC")
        )
        assertEquals(AuditDecisionSeverity.WARNING, classifyAuditDecision("PENDING"))
    }

    @Test
    fun classifyAuditDecision_deniedDecisionsMapToDenied() {
        assertEquals(AuditDecisionSeverity.DENIED, classifyAuditDecision("DENIED"))
        assertEquals(AuditDecisionSeverity.DENIED, classifyAuditDecision("BLOCKED"))
        assertEquals(AuditDecisionSeverity.DENIED, classifyAuditDecision("REJECTED"))
        assertEquals(AuditDecisionSeverity.DENIED, classifyAuditDecision("SECURITY_ERROR"))
    }
}
