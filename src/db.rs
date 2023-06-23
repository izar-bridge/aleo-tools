use std::{env::temp_dir, sync::Arc};

use once_cell::sync::OnceCell;
use serde::{de::DeserializeOwned, Serialize};

const DB_PATH: &str = "./faucet_db";

#[derive(Clone)]
pub struct RocksDB(Arc<rocksdb::DB>);

impl RocksDB {
    pub fn open() -> anyhow::Result<Self> {
        static DB: OnceCell<RocksDB> = OnceCell::new();

        // Retrieve the database.
        let database = DB
            .get_or_try_init(|| {
                // Customize database options.
                let mut options = rocksdb::Options::default();
                options.set_compression_type(rocksdb::DBCompressionType::Lz4);
                let rocksdb = {
                    options.increase_parallelism(2);
                    options.create_if_missing(true);

                    Arc::new(rocksdb::DB::open(&options, DB_PATH)?)
                };

                Ok::<_, anyhow::Error>(RocksDB(rocksdb))
            })?
            .clone();

        Ok(database)
    }

    pub fn open_map<
        K: Serialize + DeserializeOwned + Clone,
        V: Serialize + DeserializeOwned + Clone,
    >(
        prefix: &str,
    ) -> anyhow::Result<DBMap<K, V>> {
        let db = Self::open()?;

        let prefix = prefix.as_bytes().to_vec();

        Ok(DBMap {
            inner: db.inner(),
            prefix,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn test_open() -> anyhow::Result<Self> {
        static DB: OnceCell<RocksDB> = OnceCell::new();

        // Retrieve the database.
        let database = DB
            .get_or_try_init(|| {
                // Customize database options.
                let mut options = rocksdb::Options::default();
                options.set_compression_type(rocksdb::DBCompressionType::Lz4);
                let rocksdb = {
                    options.increase_parallelism(2);
                    options.create_if_missing(true);

                    Arc::new(rocksdb::DB::open(&options, temp_dir())?)
                };

                Ok::<_, anyhow::Error>(RocksDB(rocksdb))
            })?
            .clone();

        Ok(database)
    }

    pub fn test_open_map<
        K: Serialize + DeserializeOwned + Clone,
        V: Serialize + DeserializeOwned + Clone,
    >(
        prefix: &str,
    ) -> anyhow::Result<DBMap<K, V>> {
        let db = Self::test_open()?;

        let prefix = prefix.as_bytes().to_vec();

        Ok(DBMap {
            inner: db.inner(),
            prefix,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn inner(&self) -> Arc<rocksdb::DB> {
        self.0.clone()
    }
}

#[derive(Clone)]
pub struct DBMap<K: Serialize + DeserializeOwned + Clone, V: Serialize + DeserializeOwned + Clone> {
    pub inner: Arc<rocksdb::DB>,
    prefix: Vec<u8>,
    _marker: std::marker::PhantomData<(K, V)>,
}

impl<K: Serialize + DeserializeOwned + Clone, V: Serialize + DeserializeOwned + Clone> DBMap<K, V> {
    pub fn insert(&self, key: &K, value: &V) -> anyhow::Result<()> {
        let key_bytes = bincode::serialize(key)?;
        let value_bytes = bincode::serialize(value)?;

        let real_key = [self.prefix.clone(), key_bytes].concat();

        self.inner.put(real_key, value_bytes)?;

        Ok(())
    }

    pub fn batch_insert(&self, kvs: &Vec<(K, V)>) -> anyhow::Result<()> {
        let mut batch = rocksdb::WriteBatch::default();

        for (key, value) in kvs {
            let key_bytes = bincode::serialize(key)?;
            let value_bytes = bincode::serialize(value)?;

            let real_key = [self.prefix.clone(), key_bytes].concat();

            batch.put(real_key, value_bytes);
        }

        self.inner.write(batch)?;

        Ok(())
    }

    pub fn remove(&self, key: &K) -> anyhow::Result<()> {
        let key_bytes = bincode::serialize(&key)?;
        let real_key = [self.prefix.clone(), key_bytes].concat();

        self.inner.delete(real_key)?;

        Ok(())
    }

    pub fn batch_remove(&self, keys: &Vec<K>) -> anyhow::Result<()> {
        let mut batch = rocksdb::WriteBatch::default();

        for key in keys {
            let key_bytes = bincode::serialize(key)?;
            let real_key = [self.prefix.clone(), key_bytes].concat();

            batch.delete(real_key);
        }

        self.inner.write(batch)?;

        Ok(())
    }

    pub fn get_all(&self) -> anyhow::Result<Vec<(K, V)>> {
        let mut result = Vec::new();
        let iter = self.inner.prefix_iterator(self.prefix.clone());
        for item in iter {
            let (key, value) = item?;
            if key.starts_with(&self.prefix) {
                let key = &key[self.prefix.len()..];
                let key = bincode::deserialize(key)?;
                let value = bincode::deserialize(&value)?;

                result.push((key, value));
            }
        }

        Ok(result)
    }

    pub fn get(&self, key: &K) -> anyhow::Result<Option<V>> {
        let key_bytes = bincode::serialize(key)?;
        let real_key = [self.prefix.clone(), key_bytes].concat();

        let value = self.inner.get(real_key)?;

        if let Some(value) = value {
            let value = bincode::deserialize(&value)?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    pub fn pop_front(&self) -> anyhow::Result<Option<(K, V)>> {
        let mut iter = self.inner.prefix_iterator(self.prefix.clone());

        while let Some(item) = iter.next() {
            let (key, value) = item?;
            if key.starts_with(&self.prefix) {
                let key = &key[self.prefix.len()..];
                let key = bincode::deserialize(key)?;
                let value = bincode::deserialize(&value)?;

                self.remove(&key)?;

                return Ok(Some((key, value)));
            }
        }

        Ok(None)
    }

    pub fn pop_n_front(&self, num: usize) -> anyhow::Result<Vec<(K, V)>> {
        let mut result = Vec::new();
        let mut keys = Vec::new();
        let mut iter = self.inner.prefix_iterator(self.prefix.clone());

        while let Some(item) = iter.next() {
            let (key, value) = item?;
            if key.starts_with(&self.prefix) {
                let key = &key[self.prefix.len()..];
                let key: K = bincode::deserialize(key)?;
                let value = bincode::deserialize(&value)?;

                result.push((key.clone(), value));
                keys.push(key);

                if result.len() >= num {
                    break;
                }
            }
        }

        if result.len() != num {
            anyhow::bail!("pop_n_front not enough")
        } else {
            self.batch_remove(&keys)?;
            Ok(result)
        }
    }

    pub fn contain(&self, key: &K) -> anyhow::Result<bool> {
        let key_bytes = bincode::serialize(key)?;
        let real_key = [self.prefix.clone(), key_bytes].concat();

        let value = self.inner.get(real_key)?;

        Ok(value.is_some())
    }
}

#[test]
fn test_rocksdb_all_ops() {
    use rand::Rng;

    let map = RocksDB::test_open_map::<String, String>("test").unwrap();

    let mut rng = rand::thread_rng();

    for _ in 0..50 {
        let batch = rng.gen_range(0..=100);

        // insert
        let mut kvs = Vec::new();
        for _ in 0..batch {
            let key = rng.gen::<u64>().to_string();
            let value = rng.gen::<u64>().to_string();
            kvs.push((key, value));
        }
        map.batch_insert(&kvs).unwrap();

        // get
        for (key, value) in &kvs {
            let got = map.get(key).unwrap().unwrap();
            assert_eq!(got, *value);
        }

        // remove
        let remove_index = rng.gen_range(0..=batch);
        let remove_vec = kvs[remove_index..]
            .iter()
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>();

        map.batch_remove(&remove_vec).unwrap();
        for key in &remove_vec {
            let got = map.get(key).unwrap();
            assert!(got.is_none());
        }
    }
}

#[test]
fn test_insert_order() {
    use rand::Rng;

    let map = RocksDB::test_open_map::<String, String>("test").unwrap();

    let mut rng = rand::thread_rng();

    let mut kvs = Vec::new();
    for _ in 0..50 {
        let key = rng.gen::<u64>().to_string();
        let value = rng.gen::<u64>().to_string();
        kvs.push((key, value));
    }

    map.batch_insert(&kvs).unwrap();

    let mut got = map.get_all().unwrap();

    kvs.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));
    got.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));

    assert_eq!(kvs, got);
}
