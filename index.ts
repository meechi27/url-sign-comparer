import { createHmac, timingSafeEqual } from "node:crypto"

type VerifyResult =
    { status: "ok", payload: Record<string, unknown> }
    |
    { status: "rejected", reason: string };


    // TODO:add a check for the optimal key format so we can be more precise



function sign(payload: Record<string, unknown>, ttlMs: number, key: string): string {
    if (!key) throw new Error("key must be non-empty")

    if (!Number.isFinite(ttlMs) || ttlMs <= 0)
        throw new Error("ttlMs must be a positive finite number");
    // calc the current time
    const expiryDate = Date.now() + ttlMs;


    // to make the data object as one chunk
    let message;
    try {
        message = JSON.stringify({ payload, expiry: expiryDate });
    } catch (err) {
        throw new Error("Failed to serialize payload", { cause: err });
    }

    // make the machine with the key
    const tag = createHmac("sha256", key)
        .update(message) //add a message to it (added in a list and get concatenated)
        .digest("hex"); // actually returns the result as hex representation



    // encode the json string so that we can use it in the url safely
    const encodedBody = Buffer.from(message).toString("base64url");


    return encodedBody + "." + tag;
}



function verify(token: string, key: string): VerifyResult {
    if (!key) throw new Error("key must be non-empty")
    // split the token into fingerprint and data part -- then check if it has 2 parts that are non empty  
    const parts = token.split(".");
    if (parts.length !== 2 || parts[0] === "" || parts[1] === "")
        return { status: "rejected", reason: "Malformed token" };

    const [encodedBody, fingerPrint] = parts;
    // checks if the encoded body has not illegal characters for the URL
    if (!/^[A-Za-z0-9_-]+$/.test(encodedBody))
        return { status: "rejected", reason: "Malformed token" };
    // checks if the signature is formatted to HMAC 64 characters hex
    if (!/^[a-fA-F0-9]{64}$/.test(fingerPrint))
        return { status: "rejected", reason: "Invalid token signature" };

    const decoded = Buffer.from(encodedBody, "base64url").toString();
    let data: unknown;
    // takes the data and turn it into JSON
    try {
        data = JSON.parse(decoded);
    } catch {
        return { status: "rejected", reason: "Malformed token payload" };
    }
    // reconstruct the signature from the decoded data 
    const tag = createHmac("sha256", key)
        .update(decoded)
        .digest("hex");
    // turn the constructed signature and the received one into byte buffer
    const hexFingerPrint = Buffer.from(fingerPrint, "hex");
    const hexTag = Buffer.from(tag, "hex");
    // compare byte buffer length to prevent timingSafeEqual from crashing (because of non equal length buffers)
    if (hexFingerPrint.length !== hexTag.length)
        return { status: "rejected", reason: "Invalid token signature" };
    // compare same legth buffers (all x bytes comparisons have the same computing time)
    if (!timingSafeEqual(hexTag, hexFingerPrint))
        return { status: "rejected", reason: "Invalid token signature" };
    // check if data is a valid object
    if (typeof data !== "object" || data === null || Array.isArray(data))
        return { status: "rejected", reason: "Invalid token payload" };
    // treat data as object whose keys are string and data of that key is unknown
    const tokenData = data as Record<string, unknown>;

    if (typeof tokenData.expiry !== "number" || !Number.isFinite(tokenData.expiry))
        return { status: "rejected", reason: "Invalid token expiry" };

    if (tokenData.expiry <= Date.now())
        return { status: "rejected", reason: "Token expired" };

    if (typeof tokenData.payload !== "object" || tokenData.payload === null || Array.isArray(tokenData.payload))
        return { status: "rejected", reason: "Invalid token payload" };

    return { status: "ok", payload: tokenData.payload as Record<string, unknown> };

}