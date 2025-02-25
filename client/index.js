import "./index.scss";

const server = "http://localhost:3042";

document
  .getElementById("exchange-address")
  .addEventListener("input", ({ target: { value } }) => {
    if (value === "") {
      document.getElementById("balance").innerHTML = 0;
      return;
    }

    fetch(`${server}/balance/${value}`)
      .then((response) => {
        return response.json();
      })
      .then(({ balance }) => {
        document.getElementById("balance").innerHTML = balance;
      });
  });

document.getElementById("transfer-amount").addEventListener("click", () => {
  const sender = document.getElementById("exchange-address").value;
  const amount = document.getElementById("send-amount").value;
  const recipient = document.getElementById("recipient").value;

  const body = JSON.stringify({
    sender,
    amount,
    recipient,
  });

  const request = new Request(`${server}/send`, { method: "POST", body });

  fetch(request, { headers: { "Content-Type": "application/json" } })
    .then((response) => {
      return response.json();
    })
    .then((res) => {
      if (res.error) {
        return;
      }
      const { messageHash, senderPubKey, signature, amount, recipient } = res;
      const body = JSON.stringify({
        messageHash,
        senderPubKey,
        signature,
        amount,
        recipient,
      });
      const receiveRequest = new Request(`${server}/receive`, {
        method: "POST",
        body,
      });
      fetch(receiveRequest, {
        headers: { "Content-Type": "application/json" },
      })
        .then((res) => res.json())
        .then((res) => {
          if (!res.error) {
            document.getElementById("balance").innerHTML = res.balance;
          }
        });
    });
});
