import { createHmac, timingSafeEqual } from "node:crypto"

type verifyResult =
    { status: "ok", payload: Record<string, unknown> }
    |
    { status: "rejected", reason: string };


function sign(payload: Record<string, unknown>, ttlMs: number, key: string): string {
    // calc the current time

    const expiryDate = Date.now() + ttlMs;


    // to make the data object as one chunk
    const message = JSON.stringify({ payload, expiry: expiryDate });

    // make the machine with the key
    const tag = createHmac("sha256", key)
        .update(message) //add a message to it (added in a list and get concatenated)
        .digest("hex"); // actually returns the result as hex representation



    // encode the json string so that we can use it in the url safely
    const encodedBody = Buffer.from(message).toString("base64url");


    return encodedBody + "." + tag;
}



function verify(token: string, key: string): verifyResult {
    const parts = token.split(".");
    if (parts.length !== 2 || parts[0] === "" || parts[1] === "")
        return { status: "rejected", reason: "Malformed token" };

    const [encodedBody, fingerPrint] = parts;
    if (!/^[A-Za-z0-9_-]+$/.test(encodedBody))
        return { status: "rejected", reason: "Malformed token" };

    if (!/^[a-fA-F0-9]{64}$/.test(fingerPrint))
        return { status: "rejected", reason: "Invalid token signature" };

    const decoded = Buffer.from(encodedBody, "base64url").toString();
    let data: unknown;

    try {
        data = JSON.parse(decoded);
    } catch {
        return { status: "rejected", reason: "Malformed token payload" };
    }

    const tag = createHmac("sha256", key)
        .update(decoded)
        .digest("hex");

    const hexFingerPrint = Buffer.from(fingerPrint, "hex");
    const hexTag = Buffer.from(tag, "hex");

    if (hexFingerPrint.length !== hexTag.length)
        return { status: "rejected", reason: "Invalid token signature" };
    if (!timingSafeEqual(hexTag, hexFingerPrint))
        return { status: "rejected", reason: "Invalid token signature" };

    if (typeof data !== "object" || data === null || Array.isArray(data))
        return { status: "rejected", reason: "Invalid token payload" };

    const tokenData = data as Record<string, unknown>;
    if (typeof tokenData.expiry !== "number" || !Number.isFinite(tokenData.expiry))
        return { status: "rejected", reason: "Invalid token expiry" };
    if (tokenData.expiry <= Date.now())
        return { status: "rejected", reason: "Token expired" };
    if (typeof tokenData.payload !== "object" || tokenData.payload === null || Array.isArray(tokenData.payload))
        return { status: "rejected", reason: "Invalid token payload" };

    return { status: "ok", payload: tokenData.payload as Record<string, unknown> };

}