use crate::{
	backend::{Backend, StorageIterator},
	stats::StateMachineStats,
	trie_backend::{DefaultCache, DefaultRecorder, TrieBackend, TrieBackendBuilder},
	trie_backend_essence::TrieBackendStorage,
	BackendTransaction, IterArgs, StorageKey, StorageValue, TrieCacheProvider, UsageInfo,
};

use crate::backend::AsTrieBackend;
use codec::Codec;
use nomt::{hasher::Blake3Hasher, Nomt};
use sp_core::storage::{ChildInfo, StateVersion};
use std::sync::Arc;

use hash_db::Hasher;

use alloc::vec::Vec;

pub enum StateBackendBuilder<
	S: TrieBackendStorage<H>,
	H: Hasher,
	C = DefaultCache<H>,
	R = DefaultRecorder<H>,
> {
	Trie { storage: S, root: H::Out, recorder: Option<R>, cache: Option<C> },
	Nomt { db: Arc<Nomt<Blake3Hasher>>, recorder: bool },
}

impl<S, H> StateBackendBuilder<S, H>
where
	S: TrieBackendStorage<H>,
	H: Hasher,
{
	/// Create a [`TrieBackend::Trie`] state backend builder.
	pub fn new_trie(storage: S, root: H::Out) -> Self {
		Self::Trie { storage, root, recorder: None, cache: None }
	}

	/// Create a [`TrieBackend::Nomt`] state backend builder.
	pub fn new_nomt(db: Arc<Nomt<Blake3Hasher>>) -> Self {
		Self::Nomt { db, recorder: false }
	}
}

impl<S, H, C> StateBackendBuilder<S, H, C>
where
	S: TrieBackendStorage<H>,
	H: Hasher,
{
	/// Create a state backend builder.
	pub fn new_trie_with_cache(storage: S, root: H::Out, cache: C) -> Self {
		Self::Trie { storage, root, recorder: None, cache: Some(cache) }
	}

	/// Use the given optional `recorder` for the to be configured [`TrieBackend::Trie`].
	pub fn with_trie_optional_recorder(mut self, new_recorder: Option<DefaultRecorder<H>>) -> Self {
		if let StateBackendBuilder::Trie { recorder, .. } = &mut self {
			*recorder = new_recorder;
		}
		self
	}

	/// Use the given `recorder` for the to be configured [`TrieBackend::Trie`].
	pub fn with_trie_recorder(mut self, new_recorder: DefaultRecorder<H>) -> Self {
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

	pub fn build(self) -> StateBackend<S, H, C, DefaultRecorder<H>> {
		match self {
			StateBackendBuilder::Trie { storage, root, recorder, cache } => {
				let trie_backend = TrieBackendBuilder::<S, H>::new(storage, root)
					.with_optional_cache(cache)
					.with_optional_recorder(recorder)
					.build();
				StateBackend::new_trie_backend(trie_backend)
			},
			StateBackendBuilder::Nomt { db, recorder } =>
				StateBackend::new_nomt_backend(db, recorder),
		}
	}
}

enum InnerStateBackend<S: TrieBackendStorage<H>, H: Hasher, C, R> {
	Trie(TrieBackend<S, H, C, R>),
	Nomt { db: Arc<Nomt<Blake3Hasher>>, recorder: bool },
}

pub struct StateBackend<
	S: TrieBackendStorage<H>,
	H: Hasher,
	C = DefaultCache<H>,
	R = DefaultRecorder<H>,
> {
	inner: InnerStateBackend<S, H, C, R>,
}

impl<S: TrieBackendStorage<H>, H: Hasher, C, R> core::fmt::Debug for StateBackend<S, H, C, R> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match &self.inner {
			InnerStateBackend::Trie(_) => write!(f, "TrieBackend"),
			InnerStateBackend::Nomt { .. } => write!(f, "NomtBackend"),
		}
	}
}

impl<S, H, C, R> StateBackend<S, H, C, R>
where
	S: TrieBackendStorage<H>,
	H: Hasher,
{
	fn new_trie_backend(trie_backend: TrieBackend<S, H, C, R>) -> Self {
		log::info!("state_backend new_trie_backend");
		Self { inner: InnerStateBackend::Trie(trie_backend) }
	}

	fn new_nomt_backend(db: Arc<Nomt<Blake3Hasher>>, recorder: bool) -> Self {
		log::info!("state_backend new_nomt_backend");
		Self { inner: InnerStateBackend::Nomt { db, recorder } }
	}

	fn trie(&self) -> &TrieBackend<S, H, C, R> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend,
			InnerStateBackend::Nomt { .. } => unreachable!(),
		}
	}
}

impl<S, H, C, R> StateBackend<S, H, C, R>
where
	S: TrieBackendStorage<H>,
	H: Hasher,
	H::Out: Codec,
	C: TrieCacheProvider<H> + Send + Sync,
	// TODO: this will need to be more general
	R: sp_trie::TrieRecorderProvider<H> + Send + Sync,
{
	pub fn root(&self) -> &H::Out {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.root(),
			InnerStateBackend::Nomt { .. } => unreachable!(),
		}
	}
}

impl<S, H, C, R> crate::backend::Backend<H> for StateBackend<S, H, C, R>
where
	S: TrieBackendStorage<H>,
	H: Hasher,
	H::Out: Codec + Ord,
	C: TrieCacheProvider<H> + Send + Sync,
	R: sp_trie::TrieRecorderProvider<H> + Send + Sync,
{
	type Error = crate::DefaultError;
	type TrieBackendStorage = S;
	type RawIter = RawIter<S, H, C, R>;

	fn storage(&self, key: &[u8]) -> Result<Option<StorageValue>, Self::Error> {
		log::info!("state_backend storage");
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.storage(key),
			InnerStateBackend::Nomt { .. } => todo!(),
		}
	}

	fn storage_hash(&self, key: &[u8]) -> Result<Option<H::Out>, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.storage_hash(key),
			InnerStateBackend::Nomt { .. } => todo!(),
		}
	}

	fn child_storage(
		&self,
		child_info: &ChildInfo,
		key: &[u8],
	) -> Result<Option<Vec<u8>>, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.child_storage(child_info, key),
			InnerStateBackend::Nomt { .. } => todo!(),
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
			InnerStateBackend::Nomt { .. } => todo!(),
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
			InnerStateBackend::Nomt { .. } => todo!(),
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
			InnerStateBackend::Nomt { .. } => todo!(),
		}
	}

	fn next_storage_key(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) => trie_backend.next_storage_key(key),
			InnerStateBackend::Nomt { .. } => todo!(),
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
			InnerStateBackend::Nomt { .. } => todo!(),
		}
	}

	fn storage_root<'a>(
		&self,
		delta: impl Iterator<Item = (&'a [u8], Option<&'a [u8]>)>,
		state_version: StateVersion,
	) -> (H::Out, BackendTransaction<H>) {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) =>
				trie_backend.storage_root(delta, state_version),
			InnerStateBackend::Nomt { .. } => todo!(),
		}
	}

	fn child_storage_root<'a>(
		&self,
		child_info: &ChildInfo,
		delta: impl Iterator<Item = (&'a [u8], Option<&'a [u8]>)>,
		state_version: StateVersion,
	) -> (H::Out, bool, BackendTransaction<H>) {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) =>
				trie_backend.child_storage_root(child_info, delta, state_version),
			InnerStateBackend::Nomt { .. } => todo!(),
		}
	}

	fn raw_iter(&self, args: IterArgs) -> Result<Self::RawIter, Self::Error> {
		match &self.inner {
			InnerStateBackend::Trie(trie_backend) =>
				trie_backend.raw_iter(args).map(|iter| Self::RawIter::new_trie_iterator(iter)),
			InnerStateBackend::Nomt { .. } => todo!(),
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

impl<S: TrieBackendStorage<H>, H: Hasher, C> AsTrieBackend<H, C> for StateBackend<S, H, C> {
	type TrieBackendStorage = S;

	fn as_trie_backend(&self) -> &TrieBackend<S, H, C> {
		self.trie()
	}
}

enum InnerRawIter<S, H, C, R>
where
	H: Hasher,
{
	Trie(crate::trie_backend_essence::RawIter<S, H, C, R>),
	Nomt(),
}

pub struct RawIter<S, H, C, R>
where
	H: Hasher,
{
	inner: InnerRawIter<S, H, C, R>,
}

impl<S, H, C, R> RawIter<S, H, C, R>
where
	H: Hasher,
{
	pub fn new_trie_iterator(iter: crate::trie_backend_essence::RawIter<S, H, C, R>) -> Self {
		Self { inner: InnerRawIter::Trie(iter) }
	}

	pub fn new_nomt_iterator() -> Self {
		todo!()
	}
}

impl<S, H, C, R> Default for RawIter<S, H, C, R>
where
	H: Hasher,
{
	fn default() -> Self {
		Self { inner: InnerRawIter::Trie(crate::trie_backend_essence::RawIter::default()) }
	}
}

impl<S, H, C, R> StorageIterator<H> for RawIter<S, H, C, R>
where
	H: Hasher,
	H::Out: Codec + Ord,
	S: TrieBackendStorage<H>,
	C: TrieCacheProvider<H> + Send + Sync,
	R: sp_trie::TrieRecorderProvider<H> + Send + Sync,
{
	type Backend = StateBackend<S, H, C, R>;
	type Error = crate::DefaultError;

	fn next_key(
		&mut self,
		backend: &Self::Backend,
	) -> Option<core::result::Result<StorageKey, crate::DefaultError>> {
		match &mut self.inner {
			InnerRawIter::Trie(trie_iter) => trie_iter.next_key(backend.trie()),
			InnerRawIter::Nomt() => todo!(),
		}
	}

	fn next_pair(
		&mut self,
		backend: &Self::Backend,
	) -> Option<core::result::Result<(StorageKey, StorageValue), crate::DefaultError>> {
		match &mut self.inner {
			InnerRawIter::Trie(trie_iter) => trie_iter.next_pair(backend.trie()),
			InnerRawIter::Nomt() => todo!(),
		}
	}

	fn was_complete(&self) -> bool {
		match &self.inner {
			InnerRawIter::Trie(trie_iter) => trie_iter.was_complete(),
			InnerRawIter::Nomt() => todo!(),
		}
	}
}
