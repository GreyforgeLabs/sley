#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod codec;
mod maintenance;
mod repository;

pub use codec::{
    ChangedBinding, CommitMetadata, ImportedTransaction, ImportedTransactionReceipt,
    ObjectManifestEntry, TransactionCodecError, TransactionErrorCode, TransactionKind,
    TransactionReceiptRecord, TransactionRecord, build_transaction, build_transaction_receipt,
    import_transaction, import_transaction_receipt,
};
pub use maintenance::{
    RepositoryMaintenanceGuard, acquire_exclusive_repository_maintenance,
    acquire_shared_repository_maintenance, initialize_repository_maintenance,
};
pub use repository::{
    AcceptedHead, CommitError, CommitInput, CommitOutput, RecoveryReport, TransactionRepository,
    TrustedGenesisInput, VerifiedRevision,
};
