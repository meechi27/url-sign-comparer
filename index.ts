import {createHmac} from "node:crypto"




function sign(payload : Record<string,unknown>, ttlMs: number, key : string): string{
    // calc the current time
     
    const expiryDate = Date.now() + ttlMs;
    

    // to make the data object as one chunk
    const message = JSON.stringify({payload,expiry:expiryDate});

    // make the machine with the key
    const tag = createHmac("sha256",key)
    .update(message) //add a message to it (added in a list and get concatenated)
    .digest("hex"); // actually returns the result as hex representation


    
    // encode the json string so that we can use it in the url safely
    const encodedBody = Buffer.from(message).toString("base64url");


    return encodedBody + "." + tag;
}