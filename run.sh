bitcoind_rpc_user=polaruser
bitcoind_rpc_pass=polarpass
bitcoind_rpc_host=127.0.0.1
bitcoind_rpc_port=18443

ldk_storage_directory_path=.ldk/
ldk_peer_listning_port=19375

cargo run $bitcoind_rpc_user:$bitcoind_rpc_pass@$bitcoind_rpc_host:$bitcoind_rpc_port $ldk_storage_directory_path $ldk_peer_listning_port regtest
