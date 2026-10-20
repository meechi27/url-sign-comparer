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
    let data;


    if (parts.length !== 2)
        return { status: "rejected", reason: "Malformed JSON" };
    if (parts[0] === "" || parts[1] === "")
        return { status: "rejected", reason: "Malformed JSON" };


    const fingerPrint = parts[1];
    const decoded = Buffer.from(parts[0], "base64url").toString();

    try {
        data = JSON.parse(decoded);
    } catch {
        return { status: "rejected", reason: "Malformed JSON" }
    }

    // make the machine with the key
    const tag = createHmac("sha256", key)
        .update(decoded) //add a decoded message to it (added in a list and get concatenated)
        .digest("hex"); // actually returns the result as hex representation

    const hexFingerPrint = Buffer.from(fingerPrint, "hex");
    const hexTag = Buffer.from(tag, "hex");



    // check wether the token equals 
    if (hexFingerPrint.length !== hexTag.length) 
        return { status: "rejected", reason: "Invalid fingerprint" };
    if (!timingSafeEqual(hexTag, hexFingerPrint))
        return { status: "rejected", reason: "Invalid fingerprint" };
   





    return { status: "ok", payload: data.payload }

}