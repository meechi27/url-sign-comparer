import { sign, verify } from "./index";
import { expect, it } from "vitest";


it("test wether sign resulted token is valid", () => {
    const payloadTest = { user_id: 24 }
    const ttlMsTest = 5 * 10000
    const key = "test-only-secret-key-0123456789-abcdef";

    const token = sign(payloadTest, ttlMsTest, key);

    const result = verify(token, key);
    expect(result.status).toBe("ok");
    if (result.status === "ok") {
        expect(result.payload).toEqual(payloadTest);
    }
})


it("test wether valid case by code does not throw",()=>{
    const payloadTest = { user_id: 24 }
    const ttlMsTest = 5 * 10000
    const key = "test-only-secret-key-0123456789-abcdef";
    expect(()=>sign(payloadTest,1,key)).not.toThrow();
})