// Optional adapter for a user's own wallet RPC that implements eth_signTransaction.
// It signs only; the node validates bytes and broadcasts through the configured chain RPC.
export async function createWallet({chainId}) {
  const url = process.env.VOLUME_WALLET_RPC_URL;
  const address = process.env.VOLUME_WALLET_ADDRESS?.toLowerCase();
  if (!url || !/^0x[0-9a-f]{40}$/.test(address ?? '')) throw Error('SP1_OWN_WALLET_CONFIGURATION_REQUIRED');
  let id = 0;
  async function request(method, params) {
    const response = await fetch(url, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(60000),
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({jsonrpc: '2.0', id: ++id, method, params}),
    });
    if (!response.ok) throw Error('SP1_WALLET_RPC_FAILED');
    const body = await response.json();
    if (body.error || body.result === undefined) throw Error('SP1_WALLET_RPC_FAILED');
    return body.result;
  }
  if (BigInt(await request('eth_chainId', [])) !== BigInt(chainId)) throw Error('SP1_WALLET_CHAIN');
  const accounts = await request('eth_accounts', []);
  if (!accounts.some(a => a.toLowerCase() === address)) throw Error('SP1_WALLET_ACCOUNT');
  const quantity = n => `0x${BigInt(n).toString(16)}`;
  return {
    address,
    async signTransaction(tx) {
      if (tx.type !== 'eip1559' || tx.chainId !== 46630) throw Error('SP1_WALLET_CHAIN_TYPE');
      const result = await request('eth_signTransaction', [{
        type: '0x2', chainId: quantity(tx.chainId), from: address, to: tx.to,
        data: tx.data, value: quantity(tx.value), nonce: quantity(tx.nonce),
        gas: quantity(tx.gas), maxFeePerGas: quantity(tx.maxFeePerGas),
        maxPriorityFeePerGas: quantity(tx.maxPriorityFeePerGas),
      }]);
      return typeof result === 'string' ? result : result.raw;
    },
  };
}
