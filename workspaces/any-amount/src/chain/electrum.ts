const CHIPNET_SERVERS = [
  "wss://chipnet.imaginary.cash:50004",
  "wss://chipnet.bch.ninja:50004",
];

type Pending = {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
};

export class ElectrumClient {
  private ws: WebSocket | undefined;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();

  async connect(url = CHIPNET_SERVERS[0]!): Promise<void> {
    if (typeof WebSocket === "undefined") {
      throw new Error("WebSocket not available; need Node 22+");
    }
    await new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(url);
      this.ws = ws;
      const timer = setTimeout(() => reject(new Error(`electrum timeout ${url}`)), 15_000);
      ws.addEventListener("open", () => {
        clearTimeout(timer);
        resolve();
      });
      ws.addEventListener("error", () => {
        clearTimeout(timer);
        reject(new Error(`electrum error ${url}`));
      });
      ws.addEventListener("message", (ev) => {
        const msg = JSON.parse(String(ev.data)) as {
          id?: number;
          result?: unknown;
          error?: { message?: string };
        };
        if (msg.id === undefined) return;
        const p = this.pending.get(msg.id);
        if (!p) return;
        this.pending.delete(msg.id);
        if (msg.error) p.reject(new Error(msg.error.message ?? "electrum"));
        else p.resolve(msg.result);
      });
    });
  }

  async request(method: string, params: unknown[] = []): Promise<unknown> {
    if (!this.ws) throw new Error("not connected");
    const id = this.nextId++;
    const body = JSON.stringify({ id, method, params });
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws!.send(body);
      setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`electrum ${method} timed out`));
      }, 20_000);
    });
  }

  close(): void {
    this.ws?.close();
    this.ws = undefined;
  }
}

export async function connectChipnet(): Promise<ElectrumClient> {
  let last: Error | undefined;
  for (const url of CHIPNET_SERVERS) {
    const c = new ElectrumClient();
    try {
      await c.connect(url);
      return c;
    } catch (e) {
      last = e instanceof Error ? e : new Error(String(e));
    }
  }
  throw last ?? new Error("no chipnet electrum");
}

export type ElectrumUtxo = {
  tx_hash: string;
  tx_pos: number;
  value: number;
  height: number;
  token_data?: {
    category: string;
    amount?: string;
    nft?: { capability: string; commitment: string };
  };
};

export async function listUnspent(
  client: ElectrumClient,
  address: string,
): Promise<ElectrumUtxo[]> {
  const r = await client.request("blockchain.address.listunspent", [address]);
  return r as ElectrumUtxo[];
}

export async function broadcast(client: ElectrumClient, rawHex: string): Promise<string> {
  return (await client.request("blockchain.transaction.broadcast", [rawHex])) as string;
}

export async function getTx(client: ElectrumClient, txid: string): Promise<string> {
  return (await client.request("blockchain.transaction.get", [txid])) as string;
}
