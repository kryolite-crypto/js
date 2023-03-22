const Kryolite =  require('../lib/kryolite.cjs.js');

async function test()
{
    // create new address
    const address = await Kryolite.Address.Create();
    console.log("private key: " + address.PrivateKey);
    console.log("public key: " + address.PublicKey);
    console.log("address: " + address.Address);

    // import address from private key
    const imported = await Kryolite.Address.Import(address.PrivateKey);
    console.log("private key: " + imported.PrivateKey);
    console.log("public key: " + imported.PublicKey);
    console.log("address: " + imported.Address);

    // Create and sign transaction
    const transaction = new Kryolite.Transaction();
    transaction.TransactionType = Kryolite.TransactionType.PAYMENT;
    transaction.PublicKey = address.PublicKey;
    transaction.To = imported.Address;
    transaction.Value = 1_000_000; // 1 kryo
    transaction.MaxFee = 1;
    transaction.Nonce = Date.now();

    await transaction.Sign(address.PrivateKey);

    console.log(await transaction.CalculateHash());
    console.log(transaction.ToJsonString());
    console.log("verify: " + await transaction.Verify());
}

test();