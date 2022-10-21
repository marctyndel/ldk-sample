use crate::disk;
use crate::hex_utils;
use crate::{
	ChannelManager, HTLCStatus, InvoicePayer, MillisatAmount, NetworkGraph, OnionMessenger,
	PaymentInfo, PaymentInfoStorage, PeerManager,
};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::PublicKey;
use lightning::chain::keysinterface::{KeysInterface, KeysManager, Recipient};
use lightning::ln::msgs::NetAddress;
use lightning::ln::{PaymentHash, PaymentPreimage};
use lightning::onion_message::Destination;
use lightning::routing::gossip::NodeId;
use lightning::util::config::{ChannelHandshakeConfig, ChannelHandshakeLimits, UserConfig, ChannelConfig};
use lightning::util::events::EventHandler;
use lightning_invoice::payment::PaymentError;
use lightning_invoice::{utils, Currency, Invoice};
use std::env;
use std::io;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

pub(crate) struct LdkUserInfo {
	pub(crate) bitcoind_rpc_username: String,
	pub(crate) bitcoind_rpc_password: String,
	pub(crate) bitcoind_rpc_port: u16,
	pub(crate) bitcoind_rpc_host: String,
	pub(crate) ldk_storage_dir_path: String,
	pub(crate) ldk_peer_listening_port: u16,
	pub(crate) ldk_announced_listen_addr: Vec<NetAddress>,
	pub(crate) ldk_announced_node_name: [u8; 32],
	pub(crate) network: Network,
}

pub(crate) fn parse_startup_args() -> Result<LdkUserInfo, ()> {
	if env::args().len() < 3 {
		println!("ldk-tutorial-node requires 3 arguments: `cargo run <bitcoind-rpc-username>:<bitcoind-rpc-password>@<bitcoind-rpc-host>:<bitcoind-rpc-port> ldk_storage_directory_path [<ldk-incoming-peer-listening-port>] [bitcoin-network] [announced-node-name announced-listen-addr*]`");
		return Err(());
	}
	let bitcoind_rpc_info = env::args().skip(1).next().unwrap();
	let bitcoind_rpc_info_parts: Vec<&str> = bitcoind_rpc_info.rsplitn(2, "@").collect();
	if bitcoind_rpc_info_parts.len() != 2 {
		println!("ERROR: bad bitcoind RPC URL provided");
		return Err(());
	}
	let rpc_user_and_password: Vec<&str> = bitcoind_rpc_info_parts[1].split(":").collect();
	if rpc_user_and_password.len() != 2 {
		println!("ERROR: bad bitcoind RPC username/password combo provided");
		return Err(());
	}
	let bitcoind_rpc_username = rpc_user_and_password[0].to_string();
	let bitcoind_rpc_password = rpc_user_and_password[1].to_string();
	let bitcoind_rpc_path: Vec<&str> = bitcoind_rpc_info_parts[0].split(":").collect();
	if bitcoind_rpc_path.len() != 2 {
		println!("ERROR: bad bitcoind RPC path provided");
		return Err(());
	}
	let bitcoind_rpc_host = bitcoind_rpc_path[0].to_string();
	let bitcoind_rpc_port = bitcoind_rpc_path[1].parse::<u16>().unwrap();

	let ldk_storage_dir_path = env::args().skip(2).next().unwrap();

	let mut ldk_peer_port_set = true;
	let ldk_peer_listening_port: u16 = match env::args().skip(3).next().map(|p| p.parse()) {
		Some(Ok(p)) => p,
		Some(Err(_)) => {
			ldk_peer_port_set = false;
			9735
		}
		None => {
			ldk_peer_port_set = false;
			9735
		}
	};

	let mut arg_idx = match ldk_peer_port_set {
		true => 4,
		false => 3,
	};
	let network: Network = match env::args().skip(arg_idx).next().as_ref().map(String::as_str) {
		Some("testnet") => Network::Testnet,
		Some("regtest") => Network::Regtest,
		Some("signet") => Network::Signet,
		Some("bitcoin") => Network::Bitcoin,
		Some(net) => {
			panic!("Unsupported network provided. Options are: `regtest`, `testnet`, and `signet`. Got {}", net);
		}
		None => Network::Testnet,
	};

	let ldk_announced_node_name = match env::args().skip(arg_idx + 1).next().as_ref() {
		Some(s) => {
			if s.len() > 32 {
				panic!("Node Alias can not be longer than 32 bytes");
			}
			arg_idx += 1;
			let mut bytes = [0; 32];
			bytes[..s.len()].copy_from_slice(s.as_bytes());
			bytes
		}
		None => [0; 32],
	};

	let mut ldk_announced_listen_addr = Vec::new();
	loop {
		match env::args().skip(arg_idx + 1).next().as_ref() {
			Some(s) => match IpAddr::from_str(s) {
				Ok(IpAddr::V4(a)) => {
					ldk_announced_listen_addr
						.push(NetAddress::IPv4 { addr: a.octets(), port: ldk_peer_listening_port });
					arg_idx += 1;
				}
				Ok(IpAddr::V6(a)) => {
					ldk_announced_listen_addr
						.push(NetAddress::IPv6 { addr: a.octets(), port: ldk_peer_listening_port });
					arg_idx += 1;
				}
				Err(_) => panic!("Failed to parse announced-listen-addr into an IP address"),
			},
			None => break,
		}
	}

	Ok(LdkUserInfo {
		bitcoind_rpc_username,
		bitcoind_rpc_password,
		bitcoind_rpc_host,
		bitcoind_rpc_port,
		ldk_storage_dir_path,
		ldk_peer_listening_port,
		ldk_announced_listen_addr,
		ldk_announced_node_name,
		network,
	})
}

/** macro_rules! sure_writeln
 *
 * @brief Like `writeln!` but returns `()` instead of
 * `Result<(), Err>`.
 *
 * @desc In previous versions this file had a lot of
 * `println!` code to write to `stdout`, but since we
 * modified to print elsewhere, we needed to print to
 * some byte buffer instead.
 * However, `writeln!`, which we use to print to a byte
 * buffer, may fail if the destination is an ordinary
 * writeable stream or what not, so it returns `Result`,
 * which would require us to either use `.unwrap()` or 
 *`?` all the time.
 * This just adds `.unwrap()` to `writeln!`.
 */
macro_rules! sure_writeln {
	($dst: expr, $fmt: expr) => {
			writeln!($dst, $fmt).unwrap()
	};
	($dst: expr, $fmt: expr, $($arg: tt)*) => {
		{
			writeln!($dst, $fmt, $( $arg )*).unwrap()
		}
	};
}

/** macro_rules! sure_write
 *
 * @brief Like `write!` but returns `()`.
 */
macro_rules! sure_write {
	($dst: expr, $fmt: expr) => {
			write!($dst, $fmt).unwrap()
	};
	($dst: expr, $fmt: expr, $($arg: tt)*) => {
		{
			write!($dst, $fmt, $( $arg )*).unwrap()
		}
	};
}

/** handle_one_user_input
 *
 * @brief Processes and parses a single command.
 *
 * @desc This takes in the user input as a string, and
 * provides the output of the command (or any errors)
 * by writing to the given `output_buffer`.
 */
async fn handle_one_user_input<E: EventHandler>(
	user_input: String, output_buffer: &mut Vec<u8>,
	invoice_payer: Arc<InvoicePayer<E>>, peer_manager: Arc<PeerManager>,
	channel_manager: Arc<ChannelManager>, keys_manager: Arc<KeysManager>,
	network_graph: Arc<NetworkGraph>, onion_messenger: Arc<OnionMessenger>,
	inbound_payments: PaymentInfoStorage, outbound_payments: PaymentInfoStorage,
	ldk_data_dir: String, network: Network,
) {
	let line = user_input;
	let out = output_buffer;

	let mut words = line.split_whitespace();
	if let Some(word) = words.next() {
		match word {
			"help" => help(out),
			"openchannel" => {
				let peer_pubkey_and_ip_addr = words.next();
				let channel_value_sat = words.next();
				let chan_fee_base_msat = words.next();
				let chan_fee_proportional_millionths = words.next();
				if  peer_pubkey_and_ip_addr.is_none() ||
					channel_value_sat.is_none() ||
					chan_fee_base_msat.is_none() ||
					chan_fee_proportional_millionths.is_none() {
						sure_writeln!(out, "ERROR: usage `openchannel pubkey@host:port channel_amt_satoshis fee_base_msat fee_ppm_msat` [--public]");
						return;
				}
				let peer_pubkey_and_ip_addr = peer_pubkey_and_ip_addr.unwrap();
				let (pubkey, peer_addr) =
					match parse_peer_info(peer_pubkey_and_ip_addr.to_string()) {
						Ok(info) => info,
						Err(e) => {
							sure_writeln!(out, "{:?}", e.into_inner().unwrap());
							return;
						}
					};

				let chan_amt_sat: Result<u64, _> = channel_value_sat.unwrap().parse();
				let chan_fee_base_msat: Result<u32, _> = chan_fee_base_msat.unwrap().parse();
				let chan_fee_proportional_millionths: Result<u32, _> = chan_fee_proportional_millionths.unwrap().parse();
				if  chan_amt_sat.is_err() ||
					chan_fee_base_msat.is_err() ||
					chan_fee_proportional_millionths.is_err() {
						sure_writeln!(out, "ERROR: channel amount, base fee, and proportional fee must all be numbers");
						return;
				}

				// TODO: there's other configurable stuff we might want to configure
				let channel_config = ChannelConfig {
					forwarding_fee_base_msat: chan_fee_base_msat.unwrap(),
					forwarding_fee_proportional_millionths: chan_fee_proportional_millionths.unwrap(),
					..Default::default()
				};

				if connect_peer_if_necessary(out, pubkey, peer_addr, peer_manager.clone())
					.await
					.is_err()
				{
					return;
				};

				let announce_channel = match words.next() {
					Some("--public") | Some("--public=true") => true,
					Some("--public=false") => false,
					Some(_) => {
						sure_writeln!(out, "ERROR: invalid `--public` command format. Valid formats: `--public`, `--public=true` `--public=false`");
						return;
					}
					None => false,
				};

				if open_channel(
					out,
					pubkey,
					chan_amt_sat.unwrap(),
					announce_channel,
					channel_manager.clone(),
					channel_config.clone(),
				)
				.is_ok()
				{
					// todo: maybe do the persist not inside the cli parsing loop
					let peer_data_path = format!("{}/channel_peer_data", ldk_data_dir.clone());
					let _ = disk::persist_channel_peer(
						Path::new(&peer_data_path),
						peer_pubkey_and_ip_addr,
					);
				}
			}
			"sendpayment" => {
				let invoice_str = words.next();
				if invoice_str.is_none() {
					sure_writeln!(out, "ERROR: sendpayment requires an invoice: `sendpayment <invoice>`");
					return;
				}

				let invoice = match Invoice::from_str(invoice_str.unwrap()) {
					Ok(inv) => inv,
					Err(e) => {
						sure_writeln!(out, "ERROR: invalid invoice: {:?}", e);
						return;
					}
				};

				send_payment(out, &*invoice_payer, &invoice, outbound_payments.clone());
			}
			"keysend" => {
				let dest_pubkey = match words.next() {
					Some(dest) => match hex_utils::to_compressed_pubkey(dest) {
						Some(pk) => pk,
						None => {
							sure_writeln!(out, "ERROR: couldn't parse destination pubkey");
							return;
						}
					},
					None => {
						sure_writeln!(out, "ERROR: keysend requires a destination pubkey: `keysend <dest_pubkey> <amt_msat>`");
						return;
					}
				};
				let amt_msat_str = match words.next() {
					Some(amt) => amt,
					None => {
						sure_writeln!(out, "ERROR: keysend requires an amount in millisatoshis: `keysend <dest_pubkey> <amt_msat>`");
						return;
					}
				};
				let amt_msat: u64 = match amt_msat_str.parse() {
					Ok(amt) => amt,
					Err(e) => {
						sure_writeln!(out, "ERROR: couldn't parse amount_msat: {}", e);
						return;
					}
				};
				keysend(
					out,
					&*invoice_payer,
					dest_pubkey,
					amt_msat,
					&*keys_manager,
					outbound_payments.clone(),
				);
			}
			"getinvoice" => {
				let amt_str = words.next();
				if amt_str.is_none() {
					sure_writeln!(out, "ERROR: getinvoice requires an amount in millisatoshis");
					return;
				}

				let amt_msat: Result<u64, _> = amt_str.unwrap().parse();
				if amt_msat.is_err() {
					sure_writeln!(out, "ERROR: getinvoice provided payment amount was not a number");
					return;
				}

				let expiry_secs_str = words.next();
				if expiry_secs_str.is_none() {
					sure_writeln!(out, "ERROR: getinvoice requires an expiry in seconds");
					return;
				}

				let expiry_secs: Result<u32, _> = expiry_secs_str.unwrap().parse();
				if expiry_secs.is_err() {
					sure_writeln!(out, "ERROR: getinvoice provided expiry was not a number");
					return;
				}

				get_invoice(
					out,
					amt_msat.unwrap(),
					inbound_payments.clone(),
					channel_manager.clone(),
					keys_manager.clone(),
					network,
					expiry_secs.unwrap(),
				);
			}
			"connectpeer" => {
				let peer_pubkey_and_ip_addr = words.next();
				if peer_pubkey_and_ip_addr.is_none() {
					sure_writeln!(out, "ERROR: connectpeer requires peer connection info: `connectpeer pubkey@host:port`");
					return;
				}
				let (pubkey, peer_addr) =
					match parse_peer_info(peer_pubkey_and_ip_addr.unwrap().to_string()) {
						Ok(info) => info,
						Err(e) => {
							sure_writeln!(out, "{:?}", e.into_inner().unwrap());
							return;
						}
					};
				if connect_peer_if_necessary(out, pubkey, peer_addr, peer_manager.clone())
					.await
					.is_ok()
				{
					sure_writeln!(out, "SUCCESS: connected to peer {}", pubkey);
				}
			}
			"listchannels" => list_channels(out, &channel_manager, &network_graph),
			"listpayments" => {
				list_payments(out, inbound_payments.clone(), outbound_payments.clone())
			}
			"updatechannel" => {
				let channel_id_str = words.next();
				let peer_pubkey_str = words.next();
				let chan_fee_base_msat = words.next();
				let chan_fee_proportional_millionths = words.next();
				if  channel_id_str.is_none() ||
					peer_pubkey_str.is_none() ||
					chan_fee_base_msat.is_none() ||
					chan_fee_proportional_millionths.is_none() {
						sure_writeln!(out, "ERROR: usage: `updatechannel <channel_id> <peer_pubkey> <forwarding_fee_base_msat> <forwarding_fee_proportional_millionths>`");
						return;
				}
				let chan_fee_base_msat: Result<u32, _> = chan_fee_base_msat.unwrap().parse();
				let chan_fee_proportional_millionths: Result<u32, _> = chan_fee_proportional_millionths.unwrap().parse();
				if  chan_fee_base_msat.is_err() ||
					chan_fee_proportional_millionths.is_err() {
						sure_writeln!(out, "ERROR: base fee and proportional fee must all be numbers");
						return;
				}

				let channel_id_vec = hex_utils::to_vec(channel_id_str.unwrap());
				if channel_id_vec.is_none() || channel_id_vec.as_ref().unwrap().len() != 32 {
					sure_writeln!(out, "ERROR: couldn't parse channel_id");
					return;
				}
				let mut channel_id = [0; 32];
				channel_id.copy_from_slice(&channel_id_vec.unwrap());
				let peer_pubkey_vec = match hex_utils::to_vec(peer_pubkey_str.unwrap()) {
					Some(peer_pubkey_vec) => peer_pubkey_vec,
					None => {
						sure_writeln!(out, "ERROR: couldn't parse peer_pubkey");
						return;
					}
				};
				let peer_pubkey = match PublicKey::from_slice(&peer_pubkey_vec) {
					Ok(peer_pubkey) => peer_pubkey,
					Err(_) => {
						sure_writeln!(out, "ERROR: couldn't parse peer_pubkey");
						return;
					}
				};

				update_channel(
					out,
					channel_id,
					peer_pubkey,
					chan_fee_base_msat.unwrap(),
					chan_fee_proportional_millionths.unwrap(),
					channel_manager.clone()
				)
			}
			"closechannel" => {
				let channel_id_str = words.next();
				if channel_id_str.is_none() {
					sure_writeln!(out, "ERROR: closechannel requires a channel ID: `closechannel <channel_id> <peer_pubkey>`");
					return;
				}
				let channel_id_vec = hex_utils::to_vec(channel_id_str.unwrap());
				if channel_id_vec.is_none() || channel_id_vec.as_ref().unwrap().len() != 32 {
					sure_writeln!(out, "ERROR: couldn't parse channel_id");
					return;
				}
				let mut channel_id = [0; 32];
				channel_id.copy_from_slice(&channel_id_vec.unwrap());

				let peer_pubkey_str = words.next();
				if peer_pubkey_str.is_none() {
					sure_writeln!(out, "ERROR: closechannel requires a peer pubkey: `closechannel <channel_id> <peer_pubkey>`");
					return;
				}
				let peer_pubkey_vec = match hex_utils::to_vec(peer_pubkey_str.unwrap()) {
					Some(peer_pubkey_vec) => peer_pubkey_vec,
					None => {
						sure_writeln!(out, "ERROR: couldn't parse peer_pubkey");
						return;
					}
				};
				let peer_pubkey = match PublicKey::from_slice(&peer_pubkey_vec) {
					Ok(peer_pubkey) => peer_pubkey,
					Err(_) => {
						sure_writeln!(out, "ERROR: couldn't parse peer_pubkey");
						return;
					}
				};

				close_channel(out, channel_id, peer_pubkey, channel_manager.clone());
			}
			"forceclosechannel" => {
				let channel_id_str = words.next();
				if channel_id_str.is_none() {
					sure_writeln!(out, "ERROR: forceclosechannel requires a channel ID: `forceclosechannel <channel_id> <peer_pubkey>`");
					return;
				}
				let channel_id_vec = hex_utils::to_vec(channel_id_str.unwrap());
				if channel_id_vec.is_none() || channel_id_vec.as_ref().unwrap().len() != 32 {
					sure_writeln!(out, "ERROR: couldn't parse channel_id");
					return;
				}
				let mut channel_id = [0; 32];
				channel_id.copy_from_slice(&channel_id_vec.unwrap());

				let peer_pubkey_str = words.next();
				if peer_pubkey_str.is_none() {
					sure_writeln!(out, "ERROR: forceclosechannel requires a peer pubkey: `forceclosechannel <channel_id> <peer_pubkey>`");
					return;
				}
				let peer_pubkey_vec = match hex_utils::to_vec(peer_pubkey_str.unwrap()) {
					Some(peer_pubkey_vec) => peer_pubkey_vec,
					None => {
						sure_writeln!(out, "ERROR: couldn't parse peer_pubkey");
						return;
					}
				};
				let peer_pubkey = match PublicKey::from_slice(&peer_pubkey_vec) {
					Ok(peer_pubkey) => peer_pubkey,
					Err(_) => {
						sure_writeln!(out, "ERROR: couldn't parse peer_pubkey");
						return;
					}
				};

				force_close_channel(out, channel_id, peer_pubkey, channel_manager.clone());
			}
			"nodeinfo" => node_info(out, &channel_manager, &peer_manager),
			"listpeers" => list_peers(out, peer_manager.clone()),
			"signmessage" => {
				const MSG_STARTPOS: usize = "signmessage".len() + 1;
				if line.as_bytes().len() <= MSG_STARTPOS {
					sure_writeln!(out, "ERROR: signmsg requires a message");
					return;
				}
				sure_writeln!(out, 
					"{:?}",
					lightning::util::message_signing::sign(
						&line.as_bytes()[MSG_STARTPOS..],
						&keys_manager.get_node_secret(Recipient::Node).unwrap()
					)
				);
			}
			"sendonionmessage" => {
				let path_pks_str = words.next();
				if path_pks_str.is_none() {
					sure_writeln!(out, 
						"ERROR: sendonionmessage requires at least one node id for the path"
					);
					return;
				}
				let mut node_pks = Vec::new();
				let mut errored = false;
				for pk_str in path_pks_str.unwrap().split(",") {
					let node_pubkey_vec = match hex_utils::to_vec(pk_str) {
						Some(peer_pubkey_vec) => peer_pubkey_vec,
						None => {
							sure_writeln!(out, "ERROR: couldn't parse peer_pubkey");
							errored = true;
							break;
						}
					};
					let node_pubkey = match PublicKey::from_slice(&node_pubkey_vec) {
						Ok(peer_pubkey) => peer_pubkey,
						Err(_) => {
							sure_writeln!(out, "ERROR: couldn't parse peer_pubkey");
							errored = true;
							break;
						}
					};
					node_pks.push(node_pubkey);
				}
				if errored {
					return;
				}
				let destination_pk = node_pks.pop().unwrap();
				match onion_messenger.send_onion_message(
					&node_pks,
					Destination::Node(destination_pk),
					None,
				) {
					Ok(()) => sure_writeln!(out, "SUCCESS: forwarded onion message to first hop"),
					Err(e) => sure_writeln!(out, "ERROR: failed to send onion message: {:?}", e),
				}
			}
			_ => sure_writeln!(out, "Unknown command. See `\"help\" for available commands."),
		}
	}

}

pub(crate) async fn poll_for_user_input<E: EventHandler>(
	invoice_payer: Arc<InvoicePayer<E>>, peer_manager: Arc<PeerManager>,
	channel_manager: Arc<ChannelManager>, keys_manager: Arc<KeysManager>,
	network_graph: Arc<NetworkGraph>, onion_messenger: Arc<OnionMessenger>,
	inbound_payments: PaymentInfoStorage, outbound_payments: PaymentInfoStorage,
	ldk_data_dir: String, network: Network,
) {
	println!("LDK startup successful. To view available commands: \"help\".");
	println!("LDK logs are available at <your-supplied-ldk-data-dir-path>/.ldk/logs");
	println!("Local Node ID is {}.", channel_manager.get_our_node_id());
	loop {
		print!("> ");
		io::stdout().flush().unwrap(); // Without flushing, the `>` doesn't print

		/* Get input from the user.  */
		let mut line = String::new();
		if let Err(e) = io::stdin().read_line(&mut line) {
			break println!("ERROR: {e:#}");
		}
		let mut output_buffer = Vec::<u8>::new();


		/* Process that command.  */
		handle_one_user_input::<E>(
			line, &mut output_buffer,
			invoice_payer.clone(), peer_manager.clone(),
			channel_manager.clone(), keys_manager.clone(),
			network_graph.clone(), onion_messenger.clone(),
			inbound_payments.clone(), outbound_payments.clone(),
			ldk_data_dir.clone(), network
		).await;
		/* Extract the output.  Trust that the output buffer was
		 * properly UTF8-encoded.
		 */
		let output_string = unsafe { String::from_utf8_unchecked(output_buffer) };

		/* Return the output to user.  */
		print!("{}", output_string);
	}
}

fn help(out: &mut Vec<u8>) {
	sure_writeln!(out, "openchannel pubkey@host:port <amt_satoshis> [--public]");
	sure_writeln!(out, "sendpayment <invoice>");
	sure_writeln!(out, "keysend <dest_pubkey> <amt_msats>");
	sure_writeln!(out, "getinvoice <amt_msats> <expiry_secs>");
	sure_writeln!(out, "connectpeer pubkey@host:port");
	sure_writeln!(out, "listchannels");
	sure_writeln!(out, "listpayments");
	sure_writeln!(out, "closechannel <channel_id> <peer_pubkey>");
	sure_writeln!(out, "forceclosechannel <channel_id> <peer_pubkey>");
	sure_writeln!(out, "nodeinfo");
	sure_writeln!(out, "listpeers");
	sure_writeln!(out, "signmessage <message>");
}

fn node_info(
		out: &mut Vec<u8>,
		channel_manager: &Arc<ChannelManager>, peer_manager: &Arc<PeerManager>
) {
	sure_writeln!(out, "\t{{");
	sure_writeln!(out, "\t\t node_pubkey: {}", channel_manager.get_our_node_id());
	let chans = channel_manager.list_channels();
	sure_writeln!(out, "\t\t num_channels: {}", chans.len());
	sure_writeln!(out, "\t\t num_usable_channels: {}", chans.iter().filter(|c| c.is_usable).count());
	let local_balance_msat = chans.iter().map(|c| c.balance_msat).sum::<u64>();
	sure_writeln!(out, "\t\t local_balance_msat: {}", local_balance_msat);
	sure_writeln!(out, "\t\t num_peers: {}", peer_manager.get_peer_node_ids().len());
	sure_writeln!(out, "\t}},");
}

fn list_peers(out: &mut Vec<u8>, peer_manager: Arc<PeerManager>) {
	sure_writeln!(out, "\t{{");
	for pubkey in peer_manager.get_peer_node_ids() {
		sure_writeln!(out, "\t\t pubkey: {}", pubkey);
	}
	sure_writeln!(out, "\t}},");
}

fn list_channels(
		out: &mut Vec<u8>,
		channel_manager: &Arc<ChannelManager>, network_graph: &Arc<NetworkGraph>
) {
	sure_write!(out, "[");
	for chan_info in channel_manager.list_channels() {
		sure_writeln!(out, "");
		sure_writeln!(out, "\t{{");
		sure_writeln!(out, "\t\tchannel_id: {},", hex_utils::hex_str(&chan_info.channel_id[..]));
		if let Some(funding_txo) = chan_info.funding_txo {
			sure_writeln!(out, "\t\tfunding_txid: {},", funding_txo.txid);
		}

		sure_writeln!(out, 
			"\t\tpeer_pubkey: {},",
			hex_utils::hex_str(&chan_info.counterparty.node_id.serialize())
		);
		if let Some(node_info) = network_graph
			.read_only()
			.nodes()
			.get(&NodeId::from_pubkey(&chan_info.counterparty.node_id))
		{
			if let Some(announcement) = &node_info.announcement_info {
				sure_writeln!(out, "\t\tpeer_alias: {}", announcement.alias);
			}
		}

		if let Some(id) = chan_info.short_channel_id {
			sure_writeln!(out, "\t\tshort_channel_id: {},", id);
		}
		sure_writeln!(out, "\t\tis_channel_ready: {},", chan_info.is_channel_ready);
		sure_writeln!(out, "\t\tchannel_value_satoshis: {},", chan_info.channel_value_satoshis);
		sure_writeln!(out, "\t\tlocal_balance_msat: {},", chan_info.balance_msat);
		if chan_info.is_usable {
			sure_writeln!(out, "\t\tavailable_balance_for_send_msat: {},", chan_info.outbound_capacity_msat);
			sure_writeln!(out, "\t\tavailable_balance_for_recv_msat: {},", chan_info.inbound_capacity_msat);
		}
		sure_writeln!(out, "\t\tchannel_can_send_payments: {},", chan_info.is_usable);
		sure_writeln!(out, "\t\tpublic: {},", chan_info.is_public);
		sure_writeln!(out, "\t}},");
	}
	sure_writeln!(out, "]");
}

fn list_payments(
		out: &mut Vec<u8>,
		inbound_payments: PaymentInfoStorage, outbound_payments: PaymentInfoStorage
) {
	let inbound = inbound_payments.lock().unwrap();
	let outbound = outbound_payments.lock().unwrap();
	sure_write!(out, "[");
	for (payment_hash, payment_info) in inbound.deref() {
		sure_writeln!(out, "");
		sure_writeln!(out, "\t{{");
		sure_writeln!(out, "\t\tamount_millisatoshis: {},", payment_info.amt_msat);
		sure_writeln!(out, "\t\tpayment_hash: {},", hex_utils::hex_str(&payment_hash.0));
		sure_writeln!(out, "\t\thtlc_direction: inbound,");
		sure_writeln!(out, 
			"\t\thtlc_status: {},",
			match payment_info.status {
				HTLCStatus::Pending => "pending",
				HTLCStatus::Succeeded => "succeeded",
				HTLCStatus::Failed => "failed",
			}
		);

		sure_writeln!(out, "\t}},");
	}

	for (payment_hash, payment_info) in outbound.deref() {
		sure_writeln!(out, "");
		sure_writeln!(out, "\t{{");
		sure_writeln!(out, "\t\tamount_millisatoshis: {},", payment_info.amt_msat);
		sure_writeln!(out, "\t\tpayment_hash: {},", hex_utils::hex_str(&payment_hash.0));
		sure_writeln!(out, "\t\thtlc_direction: outbound,");
		sure_writeln!(out, 
			"\t\thtlc_status: {},",
			match payment_info.status {
				HTLCStatus::Pending => "pending",
				HTLCStatus::Succeeded => "succeeded",
				HTLCStatus::Failed => "failed",
			}
		);

		sure_writeln!(out, "\t}},");
	}
	sure_writeln!(out, "]");
}

pub(crate) async fn connect_peer_if_necessary(
	out: &mut Vec<u8>,
	pubkey: PublicKey, peer_addr: SocketAddr, peer_manager: Arc<PeerManager>,
) -> Result<(), ()> {
	for node_pubkey in peer_manager.get_peer_node_ids() {
		if node_pubkey == pubkey {
			return Ok(());
		}
	}
	let res = do_connect_peer(pubkey, peer_addr, peer_manager).await;
	if res.is_err() {
		sure_writeln!(out, "ERROR: failed to connect to peer");
	}
	res
}

pub(crate) async fn do_connect_peer(
	pubkey: PublicKey, peer_addr: SocketAddr, peer_manager: Arc<PeerManager>,
) -> Result<(), ()> {
	match lightning_net_tokio::connect_outbound(Arc::clone(&peer_manager), pubkey, peer_addr).await
	{
		Some(connection_closed_future) => {
			let mut connection_closed_future = Box::pin(connection_closed_future);
			loop {
				match futures::poll!(&mut connection_closed_future) {
					std::task::Poll::Ready(_) => {
						return Err(());
					}
					std::task::Poll::Pending => {}
				}
				// Avoid blocking the tokio context by sleeping a bit
				match peer_manager.get_peer_node_ids().iter().find(|id| **id == pubkey) {
					Some(_) => return Ok(()),
					None => tokio::time::sleep(Duration::from_millis(10)).await,
				}
			}
		}
		None => Err(()),
	}
}

fn update_channel(
	out: &mut Vec<u8>,
	channel_id: [u8; 32],
	counterparty_node_id: PublicKey,
	forwarding_fee_base_msat: u32,
	forwarding_fee_proportional_millionths: u32,
	channel_manager: Arc<ChannelManager>,
) {
	let channel_config = ChannelConfig {
		forwarding_fee_base_msat,
		forwarding_fee_proportional_millionths,
		..Default::default()
	};
	let channel_ids = [channel_id];
	match channel_manager.update_channel_config(
		&counterparty_node_id,
		&channel_ids,
		&channel_config
	) {
		Ok(()) => sure_writeln!(out, "EVENT: forwarding policy updated"),
		Err(e) => sure_writeln!(out, "ERROR: fwd policy update failed: {:?}", e),
	}
}

fn open_channel(
	out: &mut Vec<u8>,
	peer_pubkey: PublicKey, channel_amt_sat: u64, announced_channel: bool,
	channel_manager: Arc<ChannelManager>, channel_config: ChannelConfig
) -> Result<(), ()> {
	let config = UserConfig {
		channel_handshake_limits: ChannelHandshakeLimits {
			// lnd's max to_self_delay is 2016, so we want to be compatible.
			their_to_self_delay: 2016,
			..Default::default()
		},
		channel_handshake_config: ChannelHandshakeConfig {
			announced_channel,
			..Default::default()
		},
		channel_config,
		..Default::default()
	};

	match channel_manager.create_channel(peer_pubkey, channel_amt_sat, 0, 0, Some(config)) {
		Ok(_) => {
			sure_writeln!(out, "EVENT: initiated channel with peer {}. ", peer_pubkey);
			return Ok(());
		}
		Err(e) => {
			sure_writeln!(out, "ERROR: failed to open channel: {:?}", e);
			return Err(());
		}
	}
}

fn send_payment<E: EventHandler>(
	out: &mut Vec<u8>,
	invoice_payer: &InvoicePayer<E>, invoice: &Invoice, payment_storage: PaymentInfoStorage,
) {
	let status = match invoice_payer.pay_invoice(invoice) {
		Ok(_payment_id) => {
			let payee_pubkey = invoice.recover_payee_pub_key();
			let amt_msat = invoice.amount_milli_satoshis().unwrap();
			sure_writeln!(out, "EVENT: initiated sending {} msats to {}", amt_msat, payee_pubkey);
			HTLCStatus::Pending
		}
		Err(PaymentError::Invoice(e)) => {
			sure_writeln!(out, "ERROR: invalid invoice: {}", e);
			return;
		}
		Err(PaymentError::Routing(e)) => {
			sure_writeln!(out, "ERROR: failed to find route: {}", e.err);
			return;
		}
		Err(PaymentError::Sending(e)) => {
			sure_writeln!(out, "ERROR: failed to send payment: {:?}", e);
			HTLCStatus::Failed
		}
	};
	let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
	let payment_secret = Some(invoice.payment_secret().clone());

	let mut payments = payment_storage.lock().unwrap();
	payments.insert(
		payment_hash,
		PaymentInfo {
			preimage: None,
			secret: payment_secret,
			status,
			amt_msat: MillisatAmount(invoice.amount_milli_satoshis()),
		},
	);
}

fn keysend<E: EventHandler, K: KeysInterface>(
	out: &mut Vec<u8>,
	invoice_payer: &InvoicePayer<E>, payee_pubkey: PublicKey, amt_msat: u64, keys: &K,
	payment_storage: PaymentInfoStorage,
) {
	let payment_preimage = keys.get_secure_random_bytes();

	let status = match invoice_payer.pay_pubkey(
		payee_pubkey,
		PaymentPreimage(payment_preimage),
		amt_msat,
		40,
	) {
		Ok(_payment_id) => {
			sure_writeln!(out, "EVENT: initiated sending {} msats to {}", amt_msat, payee_pubkey);
			HTLCStatus::Pending
		}
		Err(PaymentError::Invoice(e)) => {
			sure_writeln!(out, "ERROR: invalid payee: {}", e);
			return;
		}
		Err(PaymentError::Routing(e)) => {
			sure_writeln!(out, "ERROR: failed to find route: {}", e.err);
			return;
		}
		Err(PaymentError::Sending(e)) => {
			sure_writeln!(out, "ERROR: failed to send payment: {:?}", e);
			HTLCStatus::Failed
		}
	};

	let mut payments = payment_storage.lock().unwrap();
	payments.insert(
		PaymentHash(Sha256::hash(&payment_preimage).into_inner()),
		PaymentInfo {
			preimage: None,
			secret: None,
			status,
			amt_msat: MillisatAmount(Some(amt_msat)),
		},
	);
}

fn get_invoice(
	out: &mut Vec<u8>,
	amt_msat: u64, payment_storage: PaymentInfoStorage, channel_manager: Arc<ChannelManager>,
	keys_manager: Arc<KeysManager>, network: Network, expiry_secs: u32,
) {
	let mut payments = payment_storage.lock().unwrap();
	let currency = match network {
		Network::Bitcoin => Currency::Bitcoin,
		Network::Testnet => Currency::BitcoinTestnet,
		Network::Regtest => Currency::Regtest,
		Network::Signet => Currency::Signet,
	};
	let invoice = match utils::create_invoice_from_channelmanager(
		&channel_manager,
		keys_manager,
		currency,
		Some(amt_msat),
		"ldk-tutorial-node".to_string(),
		expiry_secs,
	) {
		Ok(inv) => {
			sure_writeln!(out, "SUCCESS: generated invoice: {}", inv);
			inv
		}
		Err(e) => {
			sure_writeln!(out, "ERROR: failed to create invoice: {:?}", e);
			return;
		}
	};

	let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
	payments.insert(
		payment_hash,
		PaymentInfo {
			preimage: None,
			secret: Some(invoice.payment_secret().clone()),
			status: HTLCStatus::Pending,
			amt_msat: MillisatAmount(Some(amt_msat)),
		},
	);
}

fn close_channel(
	out: &mut Vec<u8>,
	channel_id: [u8; 32], counterparty_node_id: PublicKey, channel_manager: Arc<ChannelManager>,
) {
	match channel_manager.close_channel(&channel_id, &counterparty_node_id) {
		Ok(()) => sure_writeln!(out, "EVENT: initiating channel close"),
		Err(e) => sure_writeln!(out, "ERROR: failed to close channel: {:?}", e),
	}
}

fn force_close_channel(
	out: &mut Vec<u8>,
	channel_id: [u8; 32], counterparty_node_id: PublicKey, channel_manager: Arc<ChannelManager>,
) {
	match channel_manager.force_close_broadcasting_latest_txn(&channel_id, &counterparty_node_id) {
		Ok(()) => sure_writeln!(out, "EVENT: initiating channel force-close"),
		Err(e) => sure_writeln!(out, "ERROR: failed to force-close channel: {:?}", e),
	}
}

pub(crate) fn parse_peer_info(
	peer_pubkey_and_ip_addr: String,
) -> Result<(PublicKey, SocketAddr), std::io::Error> {
	let mut pubkey_and_addr = peer_pubkey_and_ip_addr.split("@");
	let pubkey = pubkey_and_addr.next();
	let peer_addr_str = pubkey_and_addr.next();
	if peer_addr_str.is_none() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::Other,
			"ERROR: incorrectly formatted peer info. Should be formatted as: `pubkey@host:port`",
		));
	}

	let peer_addr = peer_addr_str.unwrap().to_socket_addrs().map(|mut r| r.next());
	if peer_addr.is_err() || peer_addr.as_ref().unwrap().is_none() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::Other,
			"ERROR: couldn't parse pubkey@host:port into a socket address",
		));
	}

	let pubkey = hex_utils::to_compressed_pubkey(pubkey.unwrap());
	if pubkey.is_none() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::Other,
			"ERROR: unable to parse given pubkey for node",
		));
	}

	Ok((pubkey.unwrap(), peer_addr.unwrap().unwrap()))
}
