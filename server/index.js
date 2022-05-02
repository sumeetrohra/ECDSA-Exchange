const express = require("express");
const app = express();
const cors = require("cors");
const port = 3042;
const secp = require("@noble/secp256k1");

// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());

const balances = Array(3)
  .fill()
  .map(() => {
    const privkey = Buffer.from(secp.utils.randomPrivateKey()).toString("hex");
    return {
      privateKey: privkey,
      publicKey: Buffer.from(secp.getPublicKey(privkey)).toString("hex"),
      balance: 100,
    };
  });

console.log("Available accounts");
console.log("================================================================");
balances.forEach((item, idx) =>
  console.log(`(${idx}) 0x${item.publicKey} (${item.balance} ETH)`)
);
console.log();
console.log("Private keys");
console.log("================================================================");
balances.forEach((item, idx) => console.log(`(${idx}) 0x${item.privateKey}`));

app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const pubKey = address.replace("0x", "");
  const balance =
    balances.find((balance) => balance.publicKey === pubKey)?.balance || 0;
  res.send({ balance });
});

app.post("/send", async (req, res) => {
  const { sender, recipient, amount } = req.body;
  if (sender === recipient) {
    return res.send({ error: "Batman is watching" });
  }

  // NOTE: My wallet knows my priv key, so I don't need to put that as an input in html
  const senderPubKey = sender.replace("0x", "");
  const senderDetails = balances.find(
    (item) => item.publicKey === senderPubKey
  );
  if (!senderDetails || senderDetails.balance < amount) {
    return res.send({ error: "Insufficient funds" });
  }
  const privKeyOfSender = senderDetails.privateKey;

  // Signing the message
  const messageHash = await secp.utils.sha256(amount);
  const signature = await secp.sign(messageHash, privKeyOfSender);

  // Sending messageHash, sender pubKey and signature
  // NOTE: Not exposing any private keys
  res.send({
    messageHash: Buffer.from(messageHash).toString("hex"),
    senderPubKey,
    signature: Buffer.from(signature).toString("hex"),
    amount,
    recipient,
  });
});

app.post("/receive", async (req, res) => {
  const { messageHash, senderPubKey, signature, amount, recipient } = req.body;
  // NOTE: transaction created and broadcasted to the network
  // Verifying the signature on the chain without sending the private key or signature in the html input
  const isValid = secp.verify(signature, messageHash, senderPubKey);
  if (!isValid) {
    return res.send({ error: "Invalid signature" });
  }

  const senderDetails = balances.find(
    (item) => item.publicKey === senderPubKey
  );
  if (isValid) {
    senderDetails.balance -= amount;
    const recpPubKey = recipient.replace("0x", "");
    const recipientDetails = balances.find(
      (item) => item.publicKey === recpPubKey
    );
    if (recipientDetails) {
      recipientDetails.balance += Number(amount);
    }
    return res.send({
      balance: senderDetails.balance,
    });
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});
