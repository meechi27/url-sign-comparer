import {createHmac} from "node:crypto"

function sign(payload : Record<string,unknown>, ttlSeconds: number, key : string): string{

    // to make the data object as one chunk
    const message = JSON.stringify(payload);

    // make the machine with the key
    const tag = createHmac("sha256",key)
    .update(message) //add a message to it (added in a list and get concatenated)
    .digest("hex"); // actually returns the result as hex representation




    return ""
}