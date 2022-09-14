bitcoind_rpc_user=rt
bitcoind_rpc_pass=saloon.sawn.patron.polity.asset.basilisk
bitcoind_rpc_host=127.0.0.1
bitcoind_rpc_port=18332

ldk_storage_directory_path=/home/ubuntu/.ldk_sample/
ldk_peer_listning_port=19375

echo cargo run $bitcoind_rpc_user:$bitcoind_rpc_pass@$bitcoind_rpc_host:$bitcoind_rpc_port $ldk_storage_directory_path $ldk_peer_listning_port mainnet

#bitcoind.rpcuser=rt
#bitcoind.rpcpass=kkkkkk
#bitcoind.zmqpubrawblock=tcp://127.0.0.1:28332
#bitcoind.zmqpubrawtx=tcp://127.0.0.1:28333
