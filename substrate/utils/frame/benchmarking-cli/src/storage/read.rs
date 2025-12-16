// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use codec::Encode;
use frame_storage_access_test_runtime::StorageAccessParams;
use log::{debug, info};
use rand::prelude::*;
use sc_cli::{Error, Result};
use sc_client_api::{Backend as ClientBackend, StorageProvider, UsageProvider};
use sc_client_db::{DbHash, DbState, DbStateBuilder};
use sp_api::CallApiAt;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::{Block as BlockT, HashingFor, Header as HeaderT};
use sp_state_machine::{backend::AsTrieBackend, Backend, StorageProof};
use sp_storage::ChildInfo;
use std::{fmt::Debug, sync::Arc, time::Instant};

use super::{cmd::StorageCmd, get_wasm_module, MAX_BATCH_SIZE_FOR_BLOCK_VALIDATION};
use crate::shared::{new_rng, BenchRecord};
use nomt::{hasher::Blake3Hasher, Nomt};
use parking_lot::RwLock;

impl StorageCmd {
	/// Benchmarks the time it takes to read a single Storage item.
	/// Uses the latest state that is available for the given client.
	pub(crate) fn bench_read<B, BA, C, H>(
		&self,
		client: Arc<C>,
		nomt_db: Option<Arc<RwLock<Nomt<Blake3Hasher>>>>,
		storage: Arc<dyn sp_state_machine::Storage<HashingFor<B>>>,
		shared_trie_cache: Option<sp_trie::cache::SharedTrieCache<HashingFor<B>>>,
	) -> Result<BenchRecord>
	where
		C: UsageProvider<B> + StorageProvider<B, BA> + CallApiAt<B> + HeaderBackend<B>,
		B: BlockT<Header = H, Hash = DbHash> + Debug,
		BA: ClientBackend<B>,
		<<B as BlockT>::Header as HeaderT>::Number: From<u32>,
		H: HeaderT<Hash = DbHash>,
	{
		if self.params.is_validate_block_mode() && self.params.disable_pov_recorder {
			return Err("PoV recorder must be activated to provide a storage proof for block validation at runtime. Remove `--disable-pov-recorder` from the command line.".into())
		}
		if self.params.is_validate_block_mode() &&
			self.params.batch_size > MAX_BATCH_SIZE_FOR_BLOCK_VALIDATION
		{
			return Err(format!("Batch size is too large. This may cause problems with runtime memory allocation. Better set `--batch-size {}` or less.", MAX_BATCH_SIZE_FOR_BLOCK_VALIDATION).into())
		}

		let mut record = BenchRecord::default();
		let best_hash = client.usage_info().chain.best_hash;

		info!("Preparing keys from block {}", best_hash);
		// Load all keys and randomly shuffle them.
		let mut keys: Vec<_> = client.storage_keys(best_hash, None, None)?.collect();
		let (mut rng, _) = new_rng(None);
		keys.shuffle(&mut rng);
		if keys.is_empty() {
			return Err("Can't process benchmarking with empty storage".into())
		}

		//let mut child_nodes = Vec::new();
		// Interesting part here:
		// Read all the keys in the database and measure the time it takes to access each.
		info!("Reading {} keys", keys.len());

		// Read using the same TrieBackend and recorder for up to `batch_size` keys.
		// This would allow us to measure the amortized cost of reading a key.
		let state = client
			.state_at(best_hash)
			.map_err(|_err| Error::Input("State not found".into()))?;
		// We reassign the backend and recorder for every batch size.
		// Using a new recorder for every read vs using the same for the entire batch
		// produces significant different results. Since in the real use case we use a
		// single recorder per block, simulate the same behavior by creating a new
		// recorder every batch size, so that the amortized cost of reading a key is
		// measured in conditions closer to the real world.

		let header = client.header(best_hash)?.ok_or("Header not found")?;
		let original_root = *header.state_root();

		let (mut backend, mut recorder): (DbState<HashingFor<B>>, _) =
			self.create_state_backend::<B, H>(original_root, &storage, nomt_db.clone(), None);

		let mut read_in_batch = 0;
		let mut on_validation_size = 0;

		let last_key = keys.last().expect("Checked above to be non-empty");
		for key in keys.as_slice() {
			match (self.params.include_child_trees, self.is_child_key(key.clone().0)) {
				(true, Some(info)) => {
					// child tree key
					// TODO: handle child tries
					todo!()
				},
				_ => {
					// regular key
					let start = Instant::now();
					let v = backend
						.storage(key.0.as_ref())
						.expect("Checked above to exist")
						.ok_or("Value unexpectedly empty")?;
					on_validation_size += v.len();
					if self.params.is_import_block_mode() {
						record.append(v.len(), start.elapsed())?;
					}
				},
			}
			read_in_batch += 1;
			let is_batch_full = read_in_batch >= self.params.batch_size || key == last_key;

			// Read keys on block validation
			if is_batch_full && self.params.is_validate_block_mode() {
				// TODO: handle validate block
				todo!();
			}

			// Reload recorder
			if is_batch_full {
				(backend, recorder) = self.create_state_backend::<B, H>(
					original_root,
					&storage,
					nomt_db.clone(),
					None,
				);
				read_in_batch = 0;
			}
		}

		Ok(record)
	}
}
