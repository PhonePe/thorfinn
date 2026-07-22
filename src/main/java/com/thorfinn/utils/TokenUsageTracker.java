package com.thorfinn.utils;

import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public final class TokenUsageTracker {

    private static final AtomicLong TOTAL_PROMPT_TOKENS = new AtomicLong(0);
    private static final AtomicLong TOTAL_COMPLETION_TOKENS = new AtomicLong(0);
    private static final AtomicLong TOTAL_TOKENS = new AtomicLong(0);
    private static final AtomicLong TOTAL_CALLS = new AtomicLong(0);

    private TokenUsageTracker() {
    }

    public static void record(String source, long prompt, long completion, long total) {
        TOTAL_CALLS.incrementAndGet();
        if (total <= 0 && (prompt > 0 || completion > 0)) {
            total = prompt + completion;
        }
        TOTAL_PROMPT_TOKENS.addAndGet(Math.max(prompt, 0));
        TOTAL_COMPLETION_TOKENS.addAndGet(Math.max(completion, 0));
        TOTAL_TOKENS.addAndGet(Math.max(total, 0));
        log.info("[*] LLM token usage ({}) - prompt: {}, completion: {}, total: {}",
                source,
                prompt >= 0 ? prompt : "n/a",
                completion >= 0 ? completion : "n/a",
                total >= 0 ? total : "n/a");
    }

    public static void recordUnreported(String source) {
        TOTAL_CALLS.incrementAndGet();
        log.info("[*] LLM token usage ({}) not reported by provider", source);
    }

    public static void logScanUsage() {
        log.info("[*] ===== LLM token usage for scan =====");
        log.info("[*] LLM calls        : {}", TOTAL_CALLS.get());
        log.info("[*] Prompt tokens    : {}", TOTAL_PROMPT_TOKENS.get());
        log.info("[*] Completion tokens: {}", TOTAL_COMPLETION_TOKENS.get());
        log.info("[*] Total tokens     : {}", TOTAL_TOKENS.get());
        log.info("[*] ====================================");
    }

    public static void reset() {
        TOTAL_CALLS.set(0);
        TOTAL_PROMPT_TOKENS.set(0);
        TOTAL_COMPLETION_TOKENS.set(0);
        TOTAL_TOKENS.set(0);
    }
}

