//! The hash of the attribute table's layout, computed as a constant.
//!
//! The hash covers each attribute's kind, type, properties, security and
//! constant value, so a firmware with a changed table gets another hash. A
//! bond stores part of it, and the host compares it at the next connection to
//! learn whether the central's cached table is still valid.
