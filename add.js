import SEAL from "node-seal";
import fs from "fs";
import { execSync } from "child_process";

(async () => {
  // let list = [];
  // const download = async () => {
  //   for await (const ele of list) {
  //     const url = `https://gateway.pinata.cloud/ipfs/${ele.BallotHash}`;
  //     execSync(`curl -X GET ${url}  --output cipher/${ele.BallotHash}`);
  //   }
  // };

  // download();

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

  const savedPK = fs.readFileSync("PK");
  //
  const publicKey = seal.PublicKey();
  publicKey.load(context, savedPK);
  // const decryptor = seal.Decryptor(context, secretKey);
  const evaluator = seal.Evaluator(context);

  const dir = fs.readdirSync("cipher");
  const result = seal.CipherText();
  result.load(context, fs.readFileSync(`cipher/${dir[0]}`));

  for (let i = 1; i < dir.length; i++) {
    // console.log(i);
    const op = seal.CipherText();
    // console.log(cipher);
    const cipherFile = fs.readFileSync(`cipher/${dir[i]}`).toString();
    op.load(context, cipherFile);

    evaluator.add(result, op, result); // Op (A), Op (B), Op (Dest)
  }
  const savedResult = result.save();
  fs.writeFileSync(`RESULT`, savedResult);
})();
