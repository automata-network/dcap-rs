// src/types/pod/tcb_info/zero_copy/mod.rs

pub mod error;
pub mod structs;
pub mod iterators;

#[cfg(not(feature = "zero-copy"))]
pub mod conversion;

pub use error::ZeroCopyError;
pub use structs::{
    TcbInfoZeroCopy, 
    TdxModulePodDataZeroCopy, 
    TdxModuleIdentityZeroCopy, 
    TdxTcbLevelZeroCopy, 
    TcbLevelZeroCopy, 
    TcbComponentZeroCopy,
    // Potentially export intermediate payload structs if they are part of the public API
};
// Iterators might also be exported if users need to name their types explicitly.
// pub use iterators::*;
