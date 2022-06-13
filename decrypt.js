import SEAL from "node-seal";
import fs from "fs";

(async () => {
  const seal = await SEAL();
  const schemeType = seal.SchemeType.bfv;
  const securityLevel = seal.SecurityLevel.tc128;
  const polyModulusDegree = 4096;
  const bitSizes = [36, 36, 37];
  const bitSize = 20;
  const parms = seal.EncryptionParameters(schemeType);

  parms.setPolyModulusDegree(polyModulusDegree);

  // Create a suitable set of CoeffModulus primes
  parms.setCoeffModulus(
    seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
  );

  // Set the PlainModulus to a prime of bitSize 20.
  parms.setPlainModulus(seal.PlainModulus.Batching(polyModulusDegree, bitSize));

  const context = seal.Context(
    parms, // Encryption Parameters
    true, // ExpandModChain
    securityLevel // Enforce a security level
  );

  if (!context.parametersSet()) {
    throw new Error(
      "Could not set the parameters in the given context. Please try different encryption parameters."
    );
  }

  const encoder = seal.BatchEncoder(context);
  const sk = seal.SecretKey();
  const savedSK = fs.readFileSync(`SECRET.txt`).toString();
  sk.load(context, savedSK);

  const decryptor = seal.Decryptor(context, sk);

  const savedResult = fs.readFileSync(`RESULT`).toString();
  const result = seal.CipherText();
  result.load(context, savedResult);

  const decryptedPlainText = seal.PlainText();
  decryptor.decrypt(result, decryptedPlainText);
  let arr = encoder.decode(decryptedPlainText);

  console.log(arr);
})();
