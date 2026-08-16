import { useEffect, useState } from "react";

type AddonSDK = {
  wallet: {
    getContext: () => { walletId?: number; network?: string };
    listAddresses: () => Promise<unknown[]>;
    getPrimaryAddress?: () => Promise<string> | string;
  };
  ui: {
    confirmSensitiveAction: (args: {
      title: string;
      description: string;
      risk: "low" | "medium" | "high";
    }) => Promise<boolean>;
  };
};

type Props = { sdk: AddonSDK };

export default function ShieldedPoolApp({ sdk }: Props) {
  const [status, setStatus] = useState("Connecting");
  const [network, setNetwork] = useState("unknown");
  const [chipnet, setChipnet] = useState(false);
  const [amount, setAmount] = useState("");
  const [note, setNote] = useState(
    "Pre-release. Use the lab CLI to prove and spend. This screen only reads the local sidecar.",
  );
  const [sidecar, setSidecar] = useState("sidecar ?");

  useEffect(() => {
    try {
      const ctx = sdk.wallet.getContext();
      const net = String(ctx.network ?? "unknown");
      setNetwork(net);
      const ok = /chipnet|testnet|bchtest/i.test(net);
      setChipnet(ok);
      setStatus(ok ? "Ready" : "Wrong network — Chipnet only");
    } catch (e: unknown) {
      setStatus(e instanceof Error ? e.message : String(e));
    }
    void fetch("http://127.0.0.1:17432/status")
      .then((r) => r.json())
      .then((j: { profile?: string; circleSound?: boolean }) => {
        setSidecar(`${j.profile ?? "sidecar"} · circleSound=${String(j.circleSound)}`);
      })
      .catch(() => setSidecar("sidecar off — run npx tsx src/cli.ts serve"));
  }, [sdk]);

  const run = async (kind: "deposit" | "withdraw") => {
    if (!chipnet) {
      setNote("Switch the wallet to Chipnet first.");
      return;
    }
    const n = Number(amount);
    if (!Number.isFinite(n) || n <= 0) {
      setNote("Type an amount greater than zero.");
      return;
    }
    const ok = await sdk.ui.confirmSensitiveAction({
      title: kind === "deposit" ? "Deposit into pool" : "Withdraw from pool",
      description: `${kind} ${n} BCH on Chipnet. This stub does not build a tx. Use workspaces/any-amount CLI.`,
      risk: "medium",
    });
    setNote(ok ? `${kind} confirmed — use the lab CLI to prove and broadcast.` : "Cancelled.");
  };

  return (
    <div className="p-4 space-y-3 wallet-card rounded-2xl">
      <h2 className="text-lg font-semibold">Shielded pool</h2>
      <p className="text-sm wallet-muted">
        Chipnet · {status} · {network} · {sidecar}
      </p>
      <p className="text-sm">One pool. Type any amount. Pre-release stub.</p>
      <label className="block text-sm">
        Amount (BCH)
        <input
          className="mt-1 w-full wallet-input"
          inputMode="decimal"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          placeholder="0.37"
        />
      </label>
      <div className="flex gap-2">
        <button className="wallet-btn-primary" type="button" onClick={() => void run("deposit")}>
          Deposit
        </button>
        <button className="wallet-btn-secondary" type="button" onClick={() => void run("withdraw")}>
          Withdraw
        </button>
      </div>
      <p className="text-sm wallet-muted">{note}</p>
    </div>
  );
}
