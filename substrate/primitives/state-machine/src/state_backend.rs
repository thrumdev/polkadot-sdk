use crate::{
	backend::{Backend, StorageIterator},
	stats::StateMachineStats,
	trie_backend::{DefaultCache, TrieBackend, TrieBackendBuilder},
	trie_backend_essence::TrieBackendStorage,
	BackendTransaction, IterArgs, StorageKey, StorageProof, StorageValue, TrieCacheProvider,
	UsageInfo,
};

use crate::backend::{AsTrieBackend, NomtBackendTransaction};
use alloc::vec::Vec;
use codec::Codec;
use hash_db::Hasher;
use nomt::{
	hasher::Blake3Hasher, KeyReadWrite, KeyValueIterator, Nomt, Overlay as NomtOverlay, Session,
	SessionParams, WitnessMode,
};
use parking_lot::{ArcRwLockReadGuard, Mutex, RawRwLock, RwLock};
use sp_core::storage::{ChildInfo, StateVersion};
use sp_trie::recorder::Recorder;
use std::{
	cell::RefCell,
	collections::{BTreeMap, HashMap},
	sync::Arc,
};
use trie_db::RecordedForKey;

pub enum StateBackendBuilder<S: TrieBackendStorage<H>, H: Hasher, C = DefaultCache<H>> {
	Trie {
		storage: S,
		root: H::Out,
		recorder: Option<Recorder<H>>,
		cache: Option<C>,
	},
	Nomt {
		db: ArcRwLockReadGuard<parking_lot::RawRwLock, Nomt<Blake3Hasher>>,
		recorder: bool,
		overlay: Option<Vec<Arc<NomtOverlay>>>,
	},
}

impl<S, H> StateBackendBuilder<S, H>
where
	S: TrieBackendStorage<H>,
	H: Hasher,
	H::Out: Codec,
{
	/// Create a [`TrieBackend::Trie`] state backend builder.
	pub fn new_trie(storage: S, root: H::Out) -> Self {
		Self::Trie { storage, root, recorder: None, cache: None }
	}

	/// Create a [`TrieBackend::Nomt`] state backend builder.
	pub fn new_nomt(db: ArcRwLockReadGuard<parking_lot::RawRwLock, Nomt<Blake3Hasher>>) -> Self {
		Self::Nomt { db, recorder: false, overlay: None }
	}
}

impl<S, H, C> StateBackendBuilder<S, H, C>
where
	S: TrieBackendStorage<H>,
	H: Hasher,
	H::Out: Codec,
	C: TrieCacheProvider<H> + Send + Sync,
{
	pub fn wrap_with_recorder(backend: &StateBackend<S, H, C>) -> StateBackend<&S, H, &C> {
		match &backend.inner {
			InnerStateBackend::Trie(trie_backend) => {
				let recorder_backend = TrieBackendBuilder::wrap(trie_backend)
					.with_recorder(Default::default())
					.build();
				StateBackend { inner: InnerStateBackend::Trie(recorder_backend) }
			},
			InnerStateBackend::Nomt { recorder, session, reads, child_deltas, db } => todo!()
				// TODO: How to deal with a reference of the session which needs to be able to create another
				// session? 2 possibilities:
				// 1. Each field becomes an option form where values are 'drained' and just a flag `invalidated`
				// is kept to ensure that session is not used anymore.
				// 2. `db` would be used to create another session and an entirely new StateBackend

				// assert!(session.borrow().is_none());
				// StateBackend {
				// 	inner: InnerStateBackend::Nomt {
				// 		recorder: *recorder,
				// 		session: (,
				// 		reads: (),
				// 		child_deltas: (),
				// 		db: (),
				// 	},
				// },
		}
	}

	/// Create a state backend builder.
	pub fn new_trie_with_cache(storage: S, root: H::Out, cache: C) -> Self {
		Self::Trie { storage, root, recorder: None, cache: Some(cache) }
	}

	/// Use the given optional `recorder` for the to be configured [`TrieBackend::Trie`].
	pub fn with_trie_optional_recorder(mut self, new_recorder: Option<Recorder<H>>) -> Self {
		if let StateBackendBuilder::Trie { recorder, .. } = &mut self {
			*recorder = new_recorder;
		}
		self
	}

	/// Use the given `recorder` for the to be configured [`TrieBackend::Trie`].
	pub fn with_trie_recorder(mut self, new_recorder: Recorder<H>) -> Self {
		if let StateBackendBuilder::Trie { recorder, .. } = &mut self {
			*recorder = Some(new_recorder);
		}
		self
	}

	/// Toggle [`TrieBackend::Nomt`] recorder.
	pub fn with_nomt_recorder(mut self) -> Self {
		if let StateBackendBuilder::Nomt { recorder, .. } = &mut self {
			*recorder = true;
		}
		self
	}

	/// Toggle [`TrieBackend::Nomt`] recorder.
	pub fn with_nomt_overlay(mut self, nomt_overlay: Vec<Arc<NomtOverlay>>) -> Self {
		if let StateBackendBuilder::Nomt { overlay, .. } = &mut self {
			*overlay = Some(nomt_overlay);
		}
		self
	}

	/// Use the given optional `cache` for the to be configured [`TrieBackend::Trie`].
	pub fn with_trie_optional_cache<LC>(
		mut self,
		cache: Option<LC>,
	) -> StateBackendBuilder<S, H, LC> {
		match self {
			StateBackendBuilder::Trie { storage, root, recorder, .. } =>
				StateBackendBuilder::Trie { storage, root, recorder, cache },
			_ => unreachable!(),
		}
	}

	/// Use the given `cache` for the to be configured [`TrieBackend::Trie`].
	pub fn with_trie_cache<LC>(mut self, cache: LC) -> StateBackendBuilder<S, H, LC> {
		match self {
			StateBackendBuilder::Trie { storage, root, recorder, .. } =>
				StateBackendBuilder::Trie { storage, root, recorder, cache: Some(cache) },
			_ => unreachable!(),
		}
	}

	pub fn build(self) -> StateBackend<S, H, C> {
		match self {
			StateBackendBuilder::Trie { storage, root, recorder, cache } => {
				let trie_backend = TrieBackendBuilder::<S, H>::new(storage, root)
					.with_optional_cache(cache)
					.with_optional_recorder(recorder)
					.build();
				StateBackend::new_trie_backend(trie_backend)
			},
			StateBackendBuilder::Nomt { db, recorder, overlay } =>
				StateBackend::new_nomt_backend(db, recorder, overlay),
		}
	}
}

enum InnerStateBackend<S: TrieBackendStorage<H>, H: Hasher, C> {
	Trie(TrieBackend<S, H, C>),
	Nomt {
		recorder: bool,
		session: RefCell<Option<Session<Blake3Hasher>>>,
		reads: RefCell<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
		child_deltas: RefCell<Vec<(Vec<u8>, Option<Vec<u8>>)>>,
		// NOTE: This needs to be placed after the session so the drop order
		// unlock properly the read-locks.
		db: ArcRwLockReadGuard<parking_lot::RawRwLock, Nomt<Blake3Hasher>>,
	},
}

pub struct StateBackend<S: TrieBackendStorage<H>, H: Hasher, C = DefaultCache<H>> {
	inner: InnerStateBackend<S, H, C>,
}

impl<S: TrieBackendStorage<H>, H: Hasher, C> core::fmt::Debug for StateBackend<S, H, C> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match &self.inner {
			InnerStateBackend::Trie(_) => write!(f, "TrieBackend"),
			InnerStateBackend::Nomt { .. } => write!(f, "NomtBackend"),
		}
	}
}

impl<S, H, C> StateBackend<S, H, C>
where
	S: TrieBackendStorage<H>,
	H: Hasher,
	H::Out: Codec,
	C: TrieCacheProvider<H> + Send + Sync,
{
	fn new_trie_backend(trie_backend: TrieBackend<S, H, C>) -> Self {
		Self { inner: InnerStateBackend::Trie(trie_backend) }
	}

	fn new_nomt_backend(
		db: ArcRwLockReadGuard<parking_lot::RawRwLock, Nomt<Blake3Hasher>>,
		recorder: bool,
		overlay: Option<Vec<Arc<NomtOverlay>>>,
	) -> Self {
		let witness_mode =
			if recorder { WitnessMode::read_write() } else { WitnessMode::disabled() };
		let overlay = overlay.unwrap_or(vec![]);
		let params = SessionParams::default()
			.witness_mode(witness_mode)
			.overlay(overlay.iter().map(|o| o.as_ref()))
			.unwrap();
		let session = db.begin_session(params);

		Self {
			inner: InnerStateBackend::Nomt {
				recorder,
				session: RefCell::new(Some(session)),
				reads: RefCell::new(BTreeMap::new()),
				child_deltas: RefCell::new(vec![]),
				db,
			},
		}
	}

	pub fn extract_proof(mut self) -> Option<StorageProof> {
		match self.inner {
			InnerStateBackend::Trie(trie_backend) =>
				trie_backend.extract_proof().map(|trie_proof| StorageProof::Trie(trie_proof)),
			InnerStateBackend::Nomt { recorder, session, reads, child_deltas, db } => todo!(),
		}
	}

	fn trie(&self) -> Option<&TrieBackend<S, H, C>> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => Some(trie_backend),
			InnerStateBackend::Nomt { .. } => None,
		}
	}
}

impl<S, H, C> StateBackend<S, H, C>
where
	S: TrieBackendStorage<H>,
	H: Hasher,
	H::Out: Codec,
	C: TrieCacheProvider<H> + Send + Sync,
{
	pub fn root(&self) -> &H::Out {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.root(),
			InnerStateBackend::Nomt { .. } => unreachable!(),
		}
	}
}

fn child_trie_key(child_info: &ChildInfo, key: &[u8]) -> Vec<u8> {
	let prefix = child_info.prefixed_storage_key();
	let mut full_key = Vec::with_capacity(prefix.len() + key.len());
	full_key.extend(prefix.clone().into_inner());
	full_key.extend(key);
	full_key
}

impl<S, H, C> crate::backend::Backend<H> for StateBackend<S, H, C>
where
	S: TrieBackendStorage<H>,
	H: Hasher,
	H::Out: Codec + Ord,
	C: TrieCacheProvider<H> + Send + Sync,
{
	type Error = crate::DefaultError;
	type TrieBackendStorage = S;
	type RawIter = RawIter<S, H, C>;

	fn storage(&self, key: &[u8]) -> Result<Option<StorageValue>, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.storage(key),
			InnerStateBackend::Nomt { session, reads, recorder, .. } => {
				let val = session
					.borrow()
					.as_ref()
					.ok_or("Session must be open".to_string())?
					.read(key.to_vec())
					.map_err(|e| format!("{e:?}"))?;
				if *recorder {
					reads.borrow_mut().insert(key.to_vec(), val.clone());
				}
				Ok(val)
			},
		}
	}

	fn storage_hash(&self, key: &[u8]) -> Result<Option<H::Out>, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.storage_hash(key),
			InnerStateBackend::Nomt { session, .. } => Ok(session
				.borrow()
				.as_ref()
				.ok_or("Session must be open".to_string())?
				.read_hash(key.to_vec())
				.map_err(|e| format!("{e:?}"))?
				.map(|hash: [u8; 32]| sp_core::hash::convert_hash(&hash))),
		}
	}

	fn child_storage(
		&self,
		child_info: &ChildInfo,
		key: &[u8],
	) -> Result<Option<Vec<u8>>, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.child_storage(child_info, key),
			InnerStateBackend::Nomt { .. } => self.storage(&child_trie_key(child_info, key)),
		}
	}

	fn child_storage_hash(
		&self,
		child_info: &ChildInfo,
		key: &[u8],
	) -> Result<Option<H::Out>, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) =>
				trie_backend.child_storage_hash(child_info, key),
			InnerStateBackend::Nomt { .. } => self.storage_hash(&child_trie_key(child_info, key)),
		}
	}

	fn closest_merkle_value(
		&self,
		key: &[u8],
	) -> Result<Option<sp_trie::MerkleValue<H::Out>>, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.closest_merkle_value(key),
			InnerStateBackend::Nomt { .. } => todo!(),
		}
	}

	fn child_closest_merkle_value(
		&self,
		child_info: &ChildInfo,
		key: &[u8],
	) -> Result<Option<sp_trie::MerkleValue<H::Out>>, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) =>
				trie_backend.child_closest_merkle_value(child_info, key),
			InnerStateBackend::Nomt { .. } => todo!(),
		}
	}

	fn exists_storage(&self, key: &[u8]) -> Result<bool, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.exists_storage(key),
			InnerStateBackend::Nomt { session, .. } => {
				let exists = session
					.borrow()
					.as_ref()
					.ok_or("Session must be open".to_string())?
					.read_hash(key.to_vec())
					.map_err(|e| format!("{e:?}"))?
					.is_some();
				Ok(exists)
			},
		}
	}

	fn exists_child_storage(
		&self,
		child_info: &ChildInfo,
		key: &[u8],
	) -> Result<bool, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) =>
				trie_backend.exists_child_storage(child_info, key),
			InnerStateBackend::Nomt { .. } => self.exists_storage(&child_trie_key(child_info, key)),
		}
	}

	fn next_storage_key(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.next_storage_key(key),
			InnerStateBackend::Nomt { session, .. } => {
				let mut iter = session.borrow_mut().as_mut().unwrap().iterator(key.to_vec(), None);
				Ok(iter.next().map(|(key, _val)| key))
			},
		}
	}

	fn next_child_storage_key(
		&self,
		child_info: &ChildInfo,
		key: &[u8],
	) -> Result<Option<Vec<u8>>, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) =>
				trie_backend.next_child_storage_key(child_info, key),
			InnerStateBackend::Nomt { .. } =>
				self.next_storage_key(&child_trie_key(child_info, key)),
		}
	}

	fn storage_root<'a>(
		&self,
		delta: impl Iterator<Item = (&'a [u8], Option<&'a [u8]>)>,
		state_version: StateVersion,
	) -> (H::Out, BackendTransaction<H>) {
		// NOTE: used to benchmark how much time did it take to calculate the storage root
		// and copute the required db changes.
		// let init_time = std::time::Instant::now();
		let res = match &self.inner {
			InnerStateBackend::Trie(trie_backend) =>
				trie_backend.storage_root(delta, state_version),
			InnerStateBackend::Nomt { recorder, reads, child_deltas, session, .. } => {
				let child_deltas = std::mem::take(&mut *child_deltas.borrow_mut()).into_iter().map(
					|(key, maybe_val)| {
						(
							key.to_vec(),
							KeyReadWrite::Write(
								maybe_val.as_ref().map(|inner_val| inner_val.to_vec()),
							),
						)
					},
				);

				let mut actual_access: Vec<_> = if !*recorder {
					delta
						.into_iter()
						.map(|(key, maybe_val)| {
							let key = key.to_vec();
							// NOTE: use in case of rollbacks enabled.
							// session.borrow().as_ref().unwrap().preserve_prior_value(key.clone());
							(
								key,
								KeyReadWrite::Write(
									maybe_val.as_ref().map(|inner_val| inner_val.to_vec()),
								),
							)
						})
						.chain(child_deltas)
						.collect()
				} else {
					let mut reads = reads.borrow_mut();
					let mut actual_access = vec![];
					for (key, maybe_val) in delta.into_iter() {
						let maybe_val = maybe_val.as_ref().map(|inner_val| inner_val.to_vec());
						let key = key.to_vec();
						// NOTE: use in case of rollbacks enabled.
						// session.borrow().as_ref().unwrap().preserve_prior_value(key.clone());
						let key_read_write = match reads.remove(&key) {
							Some(prev_val) => KeyReadWrite::ReadThenWrite(prev_val, maybe_val),
							None => KeyReadWrite::Write(maybe_val),
						};
						actual_access.push((key, key_read_write));
					}
					actual_access.extend(
						std::mem::take(&mut *reads)
							.into_iter()
							.map(|(key, val)| (key, KeyReadWrite::Read(val))),
					);
					actual_access.extend(child_deltas);
					actual_access
				};

				actual_access.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));

				// NOTE: Used for debugging
				// {
				// 	use std::io::Write;
				// 	let serialization = serde_json::to_string(&actual_access).unwrap();
				// 	let mut n = 0;
				// 	let mut path_name = format!("actual{}", n);
				// 	while std::fs::exists(&path_name).unwrap() {
				// 		n += 1;
				// 		path_name = format!("actual{}", n);
				// 	}
				// 	let mut output = std::fs::File::create(path_name).unwrap();
				//     write!(output, "{}", serialization);
				// }

				// UNWRAP: Session is expected to be open.
				let mut finished = std::mem::take(&mut *session.borrow_mut())
					.unwrap()
					.finish(actual_access)
					.unwrap();
				let witness = finished.take_witness();
				let root = finished.root().into_inner();
				let overlay = finished.into_overlay();

				(
					sp_core::hash::convert_hash(&root),
					BackendTransaction::new_nomt_transaction(NomtBackendTransaction {
						transaction: overlay,
						witness,
					}),
				)
			},
		};

		//log::info!("storage root took: {}ms", init_time.elapsed().as_millis());
		res
	}

	fn child_storage_root<'a>(
		&self,
		child_info: &ChildInfo,
		delta: impl Iterator<Item = (&'a [u8], Option<&'a [u8]>)>,
		state_version: StateVersion,
	) -> Option<(H::Out, bool, BackendTransaction<H>)> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) =>
				trie_backend.child_storage_root(child_info, delta, state_version),
			InnerStateBackend::Nomt { child_deltas, .. } => {
				let prefix = child_info.prefixed_storage_key();
				let child_trie_delta: Vec<_> = delta
					.map(|(k, maybe_val)| {
						let mut full_key = Vec::with_capacity(prefix.len() + k.len());
						full_key.extend(prefix.clone().into_inner());
						full_key.extend(k);
						(full_key, maybe_val.map(|val| val.to_vec()))
					})
					.collect();
				child_deltas.borrow_mut().extend(child_trie_delta);
				None
			},
		}
	}

	fn raw_iter(&self, args: IterArgs) -> Result<Self::RawIter, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) =>
				trie_backend.raw_iter(args).map(|iter| Self::RawIter::new_trie_iterator(iter)),
			InnerStateBackend::Nomt { session, .. } => {
				Ok(Self::RawIter::new_nomt_iterator(
					// UNWRAP: Session is expected to be open.
					&mut *session.borrow_mut().as_mut().unwrap(),
					args,
				))
			},
		}
	}

	fn register_overlay_stats(&self, stats: &StateMachineStats) {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.register_overlay_stats(stats),
			InnerStateBackend::Nomt { .. } => todo!(),
		}
	}

	fn usage_info(&self) -> UsageInfo {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.usage_info(),
			InnerStateBackend::Nomt { .. } => todo!(),
		}
	}
}

impl<S: TrieBackendStorage<H>, H: Hasher, C> AsTrieBackend<H, C> for StateBackend<S, H, C>
where
	C: TrieCacheProvider<H> + Send + Sync,
	H::Out: Codec,
{
	type TrieBackendStorage = S;

	fn as_trie_backend(&self) -> &TrieBackend<S, H, C> {
		// NOTE: panic for now
		self.trie().unwrap()
	}
}

impl<S: TrieBackendStorage<H>, H: Hasher> crate::backend::AsStateBackend<H> for StateBackend<S, H> {
	type TrieBackendStorage = S;

	fn as_state_backend(&self) -> &StateBackend<S, H> {
		&self
	}
}

enum InnerRawIter<S, H, C>
where
	H: Hasher,
	H::Out: Codec,
{
	Trie(crate::trie_backend_essence::RawIter<S, H, C, Recorder<H>>),
	Nomt(RefCell<std::iter::Peekable<KeyValueIterator>>),
}

pub struct RawIter<S, H, C>
where
	H: Hasher,
	H::Out: Codec,
{
	inner: InnerRawIter<S, H, C>,
}

impl<S, H, C> RawIter<S, H, C>
where
	H: Hasher,
	H::Out: Codec,
{
	pub fn new_trie_iterator(
		iter: crate::trie_backend_essence::RawIter<S, H, C, Recorder<H>>,
	) -> Self {
		Self { inner: InnerRawIter::Trie(iter) }
	}

	pub fn new_nomt_iterator(nomt_session: &mut Session<Blake3Hasher>, args: IterArgs) -> Self {
		let start = match (&args.prefix, &args.start_at) {
			(Some(prefix), None) => prefix.to_vec(),
			(None, Some(start_at)) => start_at.to_vec(),
			(Some(prefix), Some(start_at)) => {
				assert!(start_at.starts_with(prefix));
				start_at.to_vec()
			},
			(None, None) => vec![0],
		};

		let end = if let Some(prefix) = &args.prefix {
			let mut end = prefix.to_vec();
			for byte in end.iter_mut().rev() {
				*byte = byte.wrapping_add(1);
				if *byte != 0 {
					break;
				}
			}
			Some(end)
		} else {
			None
		};

		let nomt_iter = RefCell::new(nomt_session.iterator(start.clone(), end).peekable());

		{
			let mut nomt_iter_mut = nomt_iter.borrow_mut();
			match nomt_iter_mut.peek().map(|(key, val)| key) {
				Some(first_key) if args.start_at_exclusive && *first_key == start => {
					let _ = nomt_iter_mut.next();
				},
				_ => (),
			}
		}

		Self { inner: InnerRawIter::Nomt(nomt_iter) }
	}
}

impl<S, H, C> Default for RawIter<S, H, C>
where
	H: Hasher,
	H::Out: Codec,
{
	fn default() -> Self {
		todo!("")
	}
}

impl<S, H, C> StorageIterator<H> for RawIter<S, H, C>
where
	H: Hasher,
	H::Out: Codec + Ord,
	S: TrieBackendStorage<H>,
	C: TrieCacheProvider<H> + Send + Sync,
{
	type Backend = StateBackend<S, H, C>;
	type Error = crate::DefaultError;

	fn next_key(
		&mut self,
		backend: &Self::Backend,
	) -> Option<core::result::Result<StorageKey, crate::DefaultError>> {
		match &mut self.inner {
			InnerRawIter::Trie(trie_iter) => trie_iter.next_key(backend.trie().unwrap()),
			InnerRawIter::Nomt(nomt_iter) =>
				nomt_iter.borrow_mut().next().map(|(key, _val)| Ok(key)),
		}
	}

	fn next_pair(
		&mut self,
		backend: &Self::Backend,
	) -> Option<core::result::Result<(StorageKey, StorageValue), crate::DefaultError>> {
		match &mut self.inner {
			InnerRawIter::Trie(trie_iter) => trie_iter.next_pair(backend.trie().unwrap()),
			InnerRawIter::Nomt(nomt_iter) => nomt_iter.borrow_mut().next().map(|pair| Ok(pair)),
		}
	}

	fn was_complete(&self) -> bool {
		match &self.inner {
			InnerRawIter::Trie(trie_iter) => trie_iter.was_complete(),
			InnerRawIter::Nomt(nomt_iter) => nomt_iter.borrow_mut().peek().is_some(),
		}
	}
}

#[derive(Clone)]
pub enum ProofRecorder<H: Hasher> {
	Uninit,
	Trie { recorder: Option<sp_trie::recorder::Recorder<H>> },
	Nomt {},
}

impl<H: Hasher> Default for ProofRecorder<H> {
	fn default() -> Self {
		ProofRecorder::Uninit
	}
}

impl<H: Hasher> ProofRecorder<H> {
	pub fn new() -> Self {
		ProofRecorder::Uninit
	}

	pub fn with_ignored_nodes(ignored_nodes: sp_trie::recorder::IgnoredNodes<H::Out>) -> Self {
		ignored_nodes.assert_empty();
		ProofRecorder::Uninit
	}

	pub fn as_trie_recorder(&self, storage_root: H::Out) -> sp_trie::recorder::TrieRecorder<'_, H> {
		match self {
			ProofRecorder::Trie { recorder: Some(ref trie_recorder) } =>
				trie_recorder.as_trie_recorder(storage_root),
			_ => unreachable!(),
		}
	}

	pub fn drain_storage_proof(self) -> StorageProof {
		// NOTE: The external recorder needs to be able to drain the proof from the backend.
		todo!()
	}

	pub fn to_storage_proof(&self) -> StorageProof {
		todo!()
	}

	pub fn estimate_encoded_size(&self) -> usize {
		todo!()
	}

	pub fn reset(&self) {
		todo!()
	}

	pub fn recorded_keys(&self) -> HashMap<H::Out, HashMap<Arc<[u8]>, RecordedForKey>> {
		todo!()
	}
	pub fn start_transaction(&self) {
		todo!()
	}
	pub fn rollback_transaction(&self) -> Result<(), ()> {
		todo!()
	}
	pub fn commit_transaction(&self) -> Result<(), ()> {
		todo!()
	}
}

impl<H: Hasher> sp_trie::ProofSizeProvider for ProofRecorder<H> {
	fn estimate_encoded_size(&self) -> usize {
		todo!()
	}
}
