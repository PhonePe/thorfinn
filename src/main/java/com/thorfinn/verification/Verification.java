package com.thorfinn.verification;

import com.thorfinn.models.Finding;
import com.thorfinn.models.VerificationResult;

public interface Verification {
    VerificationResult verify(Finding finding) throws Exception;
}
