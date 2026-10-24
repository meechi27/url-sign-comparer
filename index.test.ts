
import { createHmac } from "node:crypto";
import { sign, verify } from "./index";
import { afterEach, describe, expect, it, vi } from "vitest";

const key = "test-only-secret-key-0123456789-abcdef";
const wrongKey = "test-boby-secret-key-0123456789-abcdef";
const payload = { user_id: 24 };
const ttlMs = 50_000;

// Creates a signature for custom test payloads.
function createSignature(message: string, secret: string): string {
    return createHmac("sha256", secret).update(message).digest("hex");
}

// Creates a token whose body can be customized for rejection tests.
function createCustomToken(message: string, secret: string): string {
    const body = Buffer.from(message).toString("base64url");
    const signature = createSignature(message, secret);
    return `${body}.${signature}`;
}

describe("sign()", () => {
    it("creates a token that verify() accepts", () => {
        const token = sign(payload, ttlMs, key);
        const result = verify(token, key);

        expect(result.status).toBe("ok");
        if (result.status === "ok") {
            expect(result.payload).toEqual(payload);
        }
    });

    it("rejects an empty key", () => {
        expect(() => sign(payload, ttlMs, "")).toThrow(
            "key must be at least 32 bytes"
        );
    });

    it("rejects a key shorter than 32 bytes", () => {
        expect(() => sign(payload, ttlMs, "a".repeat(31))).toThrow(
            "key must be at least 32 bytes"
        );
    });

    it("accepts a key exactly 32 bytes long", () => {
        expect(() => sign(payload, ttlMs, "a".repeat(32))).not.toThrow();
    });

    it.each([0, -1, NaN, Infinity, -Infinity])(
        "rejects invalid ttlMs: %s",
        (invalidTtl) => {
            expect(() => sign(payload, invalidTtl, key)).toThrow(
                "ttlMs must be a positive finite number"
            );
        }
    );

    it("rejects a circular payload", () => {
        const circular: Record<string, unknown> = {};
        circular.self = circular;

        expect(() => sign(circular, ttlMs, key)).toThrow(
            "Failed to serialize payload"
        );
    });
});

describe("verify()", () => {
    it("accepts a valid token and returns its payload", () => {
        const token = sign(payload, ttlMs, key);

        expect(verify(token, key)).toEqual({
            status: "ok",
            payload
        });
    });

    it("rejects an empty key", () => {
        expect(() => verify("anything", "")).toThrow(
            "key must be at least 32 bytes"
        );
    });

    it("rejects a key shorter than 32 bytes", () => {
        expect(() => verify("anything", "a".repeat(31))).toThrow(
            "key must be at least 32 bytes"
        );
    });

    it.each([
        "",
        "invalidtoken",
        ".signature",
        "body.",
        "body.signature.extra"
    ])("rejects malformed token structure: %s", (token) => {
        expect(verify(token, key)).toEqual({
            status: "rejected",
            reason: "Malformed token"
        });
    });

    it("rejects invalid Base64URL characters", () => {
        expect(verify("@@@.abcdef", key)).toEqual({
            status: "rejected",
            reason: "Malformed token"
        });
    });

    it("rejects an invalid signature format", () => {
        expect(verify("YWJj.xyz", key)).toEqual({
            status: "rejected",
            reason: "Invalid token signature"
        });
    });

    it("rejects a body that is not valid JSON", () => {
        const token = createCustomToken("not json", key);

        expect(verify(token, key)).toEqual({
            status: "rejected",
            reason: "Malformed token payload"
        });
    });

    it("rejects a token signed with a different key", () => {
        const token = sign(payload, ttlMs, key);

        expect(verify(token, wrongKey)).toEqual({
            status: "rejected",
            reason: "Invalid token signature"
        });
    });

    it("rejects a token with a tampered signature", () => {
        const token = sign(payload, ttlMs, key);
        const [body, signature] = token.split(".");
        const modifiedSignature =
            signature.endsWith("a")
                ? signature.slice(0, -1) + "b"
                : signature.slice(0, -1) + "a";

        expect(verify(`${body}.${modifiedSignature}`, key)).toEqual({
            status: "rejected",
            reason: "Invalid token signature"
        });
    });

    it("rejects a correctly signed JSON array", () => {
        const token = createCustomToken("[1,2,3]", key);

        expect(verify(token, key)).toEqual({
            status: "rejected",
            reason: "Invalid token payload"
        });
    });

    it("rejects a token without an expiry", () => {
        const token = createCustomToken(
            JSON.stringify({ payload }),
            key
        );

        expect(verify(token, key)).toEqual({
            status: "rejected",
            reason: "Invalid token expiry"
        });
    });

    it("rejects a token with a non-numeric expiry", () => {
        const token = createCustomToken(
            JSON.stringify({ payload, expiry: "tomorrow" }),
            key
        );

        expect(verify(token, key)).toEqual({
            status: "rejected",
            reason: "Invalid token expiry"
        });
    });

    it("rejects an expired token", () => {
        const token = createCustomToken(
            JSON.stringify({
                payload,
                expiry: Date.now() - 1000
            }),
            key
        );

        expect(verify(token, key)).toEqual({
            status: "rejected",
            reason: "Token expired"
        });
    });

    it("rejects a null payload", () => {
        const token = createCustomToken(
            JSON.stringify({
                payload: null,
                expiry: Date.now() + 60_000
            }),
            key
        );

        expect(verify(token, key)).toEqual({
            status: "rejected",
            reason: "Invalid token payload"
        });
    });

    it("rejects an array payload", () => {
        const token = createCustomToken(
            JSON.stringify({
                payload: [1, 2, 3],
                expiry: Date.now() + 60_000
            }),
            key
        );

        expect(verify(token, key)).toEqual({
            status: "rejected",
            reason: "Invalid token payload"
        });
    });
});


describe("additional edge cases", () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    // 1. Token is still valid just before expiry.
    it("accepts a token before expiry", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));

        const token = sign(payload, 1000, key);

        vi.advanceTimersByTime(999);

        expect(verify(token, key)).toEqual({
            status: "ok",
            payload
        });
    });

    // 2. Token is rejected after its TTL has elapsed.
    it("rejects a token after expiry", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));

        const token = sign(payload, 1000, key);

        vi.advanceTimersByTime(1001);

        expect(verify(token, key)).toEqual({
            status: "rejected",
            reason: "Token expired"
        });
    });

    // 3. Expiry equal to the current time counts as expired.
    it("rejects a token when expiry equals the current time", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));

        const message = JSON.stringify({
            payload,
            expiry: Date.now()
        });

        const token = createCustomToken(message, key);

        expect(verify(token, key)).toEqual({
            status: "rejected",
            reason: "Token expired"
        });
    });

    // 4. A null expiry is invalid.
    it("rejects a null expiry", () => {
        const message = JSON.stringify({
            payload,
            expiry: null
        });

        const token = createCustomToken(message, key);

        expect(verify(token, key)).toEqual({
            status: "rejected",
            reason: "Invalid token expiry"
        });
    });

    // 5, 6, 7. Top-level JSON must be an object.
    it.each([
        { label: "string", message: JSON.stringify("hello") },
        { label: "number", message: JSON.stringify(123) },
        { label: "boolean", message: JSON.stringify(true) }
    ])("rejects a top-level JSON $label", ({ message }) => {
        const token = createCustomToken(message, key);

        expect(verify(token, key)).toEqual({
            status: "rejected",
            reason: "Invalid token payload"
        });
    });

    // 8. Nested payload data should survive signing and verification.
    it("preserves nested payload data", () => {
        const nestedPayload = {
            user_id: 24,
            metadata: {
                roles: ["admin", "editor"],
                active: true
            }
        };

        const token = sign(nestedPayload, ttlMs, key);

        expect(verify(token, key)).toEqual({
            status: "ok",
            payload: nestedPayload
        });
    });

    // 9. Uppercase hexadecimal signatures should be accepted.
    it("accepts an uppercase hexadecimal signature", () => {
        const token = sign(payload, ttlMs, key);
        const [body, signature] = token.split(".");

        const uppercaseToken = `${body}.${signature.toUpperCase()}`;

        expect(verify(uppercaseToken, key)).toEqual({
            status: "ok",
            payload
        });
    });

    // 10. Key validation measures UTF-8 bytes, not character count.
    it("accepts a Unicode key with 32 UTF-8 bytes", () => {
        const unicodeKey = "é".repeat(16);

        expect(unicodeKey.length).toBe(16);
        expect(Buffer.byteLength(unicodeKey, "utf8")).toBe(32);

        const token = sign(payload, ttlMs, unicodeKey);

        expect(verify(token, unicodeKey)).toEqual({
            status: "ok",
            payload
        });
    });
});

it("rejects a non-canonical Base64URL body", () => {
    const message = JSON.stringify({
        payload: { user_id: 24 },
        expiry: Date.now() + 60_000
    });

    const body = Buffer.from(message).toString("base64url");
    const signature = createHmac("sha256", key)
        .update(message)
        .digest("hex");

    // Change the last Base64URL character without changing decoded bytes.
    const lastChar = body.at(-1)!;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const index = alphabet.indexOf(lastChar);
    const replacement = alphabet[(index & 48) + 1];

    const nonCanonicalBody = body.slice(0, -1) + replacement;

    expect(Buffer.from(nonCanonicalBody, "base64url")).toEqual(
        Buffer.from(body, "base64url")
    );

    expect(verify(`${nonCanonicalBody}.${signature}`, key).status)
        .toBe("rejected");
});